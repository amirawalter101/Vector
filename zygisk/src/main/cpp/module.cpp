#include <android/log.h>
#include <common/config.h>
#include <common/logging.h>
#include <core/context.h>
#include <core/native_api.h>
#include <elf.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>
#include <fcntl.h>
#include <jni/jni_bridge.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <zygisk.hpp>

#include "ipc_bridge.h"

#define VLOGI(...) __android_log_print(ANDROID_LOG_INFO, "VectorInline", __VA_ARGS__)
#define VLOGW(...) __android_log_print(ANDROID_LOG_WARN, "VectorInline", __VA_ARGS__)

namespace vector::native::module {

namespace {

#if defined(__LP64__)
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Phdr = Elf64_Phdr;
#else
using Elf_Ehdr = Elf32_Ehdr;
using Elf_Phdr = Elf32_Phdr;
#endif

std::mutex g_hooks_mutex;
std::vector<void *> g_art_hooks;
bool g_record_hooks = false;

bool ReadExact(int fd, void *buf, size_t len) {
    auto *p = static_cast<uint8_t *>(buf);
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

bool WriteExact(int fd, const void *buf, size_t len) {
    const auto *p = static_cast<const uint8_t *>(buf);
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

std::string Trim(std::string_view sv) {
    const auto first = sv.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = sv.find_last_not_of(" \t\r\n");
    return std::string(sv.substr(first, last - first + 1));
}

bool MatchesStream(std::istream &stream, const std::string &proc) {
    std::string line;
    while (std::getline(stream, line)) {
        if (auto pos = line.find('#'); pos != std::string::npos) line.erase(pos);
        std::string entry = Trim(line);
        if (entry.empty()) continue;
        if (entry == "*" || proc == entry) return true;
        if (proc.size() > entry.size() && proc.compare(0, entry.size(), entry) == 0 &&
            proc[entry.size()] == ':') {
            return true;
        }
    }
    return false;
}

bool MatchesModuleDirFile(int dir_fd, const std::string &proc) {
    if (dir_fd < 0) return false;
    int fd = openat(dir_fd, "invalidate_inline.txt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    std::string content;
    char buf[512];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    std::istringstream iss(content);
    return MatchesStream(iss, proc);
}

void CompanionHandler(int client_fd) {
    uint32_t len = 0;
    if (!ReadExact(client_fd, &len, sizeof(len)) || len == 0 || len > 4096) return;
    std::string proc(len, '\0');
    if (!ReadExact(client_fd, proc.data(), len)) return;

    static constexpr const char *kPaths[] = {
        "/data/adb/vector/invalidate_inline.txt",
        "/data/adb/lspd/invalidate_inline.txt",
        "/data/adb/modules/zygisk_vector/invalidate_inline.txt",
    };
    uint8_t matched = 0;
    for (const char *path : kPaths) {
        std::ifstream f(path);
        if (f.is_open() && MatchesStream(f, proc)) {
            matched = 1;
            break;
        }
    }
    WriteExact(client_fd, &matched, sizeof(matched));
}

bool ShouldInvalidate(zygisk::Api *api, const char *nice_name) {
    if (!api || !nice_name || nice_name[0] == '\0') return false;
    std::string proc(nice_name);

    if (MatchesModuleDirFile(api->getModuleDir(), proc)) return true;

    int fd = api->connectCompanion();
    if (fd >= 0) {
        auto len = static_cast<uint32_t>(proc.size());
        uint8_t matched = 0;
        bool ok = WriteExact(fd, &len, sizeof(len)) && WriteExact(fd, proc.data(), len) &&
                  ReadExact(fd, &matched, sizeof(matched));
        close(fd);
        if (ok && matched != 0) return true;
    }
    return false;
}

// Restores libart.so executable bytes directly from the clean ELF on disk.
// Uses mprotect + memcpy, matching LSPosed v2.2.1's imports.
size_t CleanupLibArtFromDisk(const char *proc_name) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        VLOGW("Failed to open /proc/self/maps for '%s'", proc_name);
        return 0;
    }

    struct ExecVma {
        uintptr_t start;
        uintptr_t end;
        uintptr_t offset;
    };

    std::string art_path;
    std::vector<ExecVma> exec_vmas;
    bool found = false;

    std::string line;
    while (std::getline(maps, line)) {
        uintptr_t start = 0, end = 0, offset = 0;
        char perms[5] = {};
        int path_pos = 0;
        if (sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %*x:%*x %*u %n",
                   &start, &end, perms, &offset, &path_pos) < 4) {
            continue;
        }
        if (path_pos <= 0 || static_cast<size_t>(path_pos) >= line.size()) continue;
        std::string path = Trim(std::string_view(line).substr(path_pos));
        if (!path.ends_with("/libart.so")) continue;

        if (art_path.empty()) art_path = path;
        if (path != art_path) continue;
        if (perms[2] != 'x') continue;

        exec_vmas.push_back({start, end, offset});
        found = true;
    }

    if (!found) {
        VLOGW("libart.so executable mapping not found for '%s'", proc_name);
        return 0;
    }

    int fd = open(art_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        VLOGW("Failed to open %s: errno=%d", art_path.c_str(), errno);
        return 0;
    }

    const size_t page_sz = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    size_t cleaned = 0;

    for (const auto &vma : exec_vmas) {
        uintptr_t page_start = vma.start & ~(page_sz - 1);
        uintptr_t page_end = (vma.end + page_sz - 1) & ~(page_sz - 1);
        size_t map_len = page_end - page_start;
        size_t copy_len = vma.end - vma.start;

        std::vector<uint8_t> clean(copy_len);
        ssize_t rd = pread(fd, clean.data(), copy_len, static_cast<off_t>(vma.offset));
        if (rd <= 0) continue;

        // Two-step mprotect to avoid SELinux execmod denial in app context.
        if (mprotect(reinterpret_cast<void *>(page_start), map_len, PROT_READ | PROT_WRITE) != 0) {
            VLOGW("mprotect RW failed for %" PRIxPTR " errno=%d", page_start, errno);
            continue;
        }

        memcpy(reinterpret_cast<void *>(vma.start), clean.data(), copy_len);

        mprotect(reinterpret_cast<void *>(page_start), map_len, PROT_READ | PROT_EXEC);
        __builtin___clear_cache(reinterpret_cast<char *>(vma.start),
                                reinterpret_cast<char *>(vma.end));
        ++cleaned;
    }

    close(fd);
    VLOGI("Cleaned %zu executable segment(s) of libart.so from disk for '%s'", cleaned, proc_name);
    return cleaned;
}

}  // namespace

constexpr int FIRST_ISOLATED_UID = 99000;
constexpr int LAST_ISOLATED_UID = 99999;
constexpr int FIRST_APP_ZYGOTE_ISOLATED_UID = 90000;
constexpr int LAST_APP_ZYGOTE_ISOLATED_UID = 98999;
constexpr int SHARED_RELRO_UID = 1037;
constexpr int PER_USER_RANGE = 100000;

constexpr uid_t kHostPackageUid = INJECTED_PACKAGE_UID;
const char *const kHostPackageName = INJECTED_PACKAGE_NAME;
const char *const kManagerPackageName = MANAGER_PACKAGE_NAME;
constexpr uid_t GID_INET = 3003;

enum RuntimeFlags : uint32_t {
    LATE_INJECT = 1 << 30,
};

using obfuscation_map_t = std::map<std::string, std::string>;
class ConfigImpl : public ConfigBridge {
public:
    inline static void Init() { instance_ = std::make_unique<ConfigImpl>(); }
    virtual obfuscation_map_t &obfuscation_map() override { return obfuscation_map_; }
    virtual void obfuscation_map(obfuscation_map_t m) override { obfuscation_map_ = std::move(m); }

private:
    ConfigImpl() = default;
    friend std::unique_ptr<ConfigImpl> std::make_unique<ConfigImpl>();
    obfuscation_map_t obfuscation_map_;
};

class VectorModule : public zygisk::ModuleBase, public vector::native::Context {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override;
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override;
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override;
    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override;
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override;

protected:
    void LoadDex(JNIEnv *env, PreloadedDex &&dex) override;
    void SetupEntryClass(JNIEnv *env) override;

private:
    void SetAllowUnload(bool unload);

    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;

    const lsplant::InitInfo init_info_{
        .inline_hooker =
            [](auto target, auto replace) {
                void *backup = nullptr;
                if (HookInline(target, replace, &backup) != 0) return static_cast<void *>(nullptr);

                std::lock_guard<std::mutex> lock(g_hooks_mutex);
                if (g_record_hooks &&
                    std::find(g_art_hooks.begin(), g_art_hooks.end(), target) ==
                        g_art_hooks.end()) {
                    g_art_hooks.push_back(target);
                }
                return backup;
            },
        .inline_unhooker = [](auto target) { return UnhookInline(target) == 0; },
        .art_symbol_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbPrefixFirstAddress(symbol); },
        .generated_class_name = "Vector_",
        .generated_source_name = "Dobby",
    };

    bool should_inject_ = false;
    bool is_manager_app_ = false;
    bool should_invalidate_ = false;
};

void VectorModule::LoadDex(JNIEnv *env, PreloadedDex &&dex) {
    LOGV("Loading framework DEX into memory (size: {}).", dex.size());

    auto classloader_class = lsplant::JNI_FindClass(env, "java/lang/ClassLoader");
    if (!classloader_class) {
        LOGE("Failed to find java.lang.ClassLoader");
        return;
    }
    auto getsyscl_mid = lsplant::JNI_GetStaticMethodID(
        env, classloader_class.get(), "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    auto system_classloader =
        lsplant::JNI_CallStaticObjectMethod(env, classloader_class.get(), getsyscl_mid);
    if (!system_classloader) {
        LOGE("Failed to get SystemClassLoader");
        return;
    }

    auto byte_buffer_class = lsplant::JNI_FindClass(env, "java/nio/ByteBuffer");
    if (!byte_buffer_class) {
        LOGE("Failed to find java.nio.ByteBuffer");
        return;
    }
    auto dex_buffer =
        lsplant::ScopedLocalRef(env, env->NewDirectByteBuffer(dex.data(), dex.size()));
    if (!dex_buffer) {
        LOGE("Failed to create DirectByteBuffer for DEX.");
        return;
    }

    auto in_memory_cl_class = lsplant::JNI_FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (!in_memory_cl_class) {
        LOGE("Failed to find InMemoryDexClassLoader.");
        return;
    }
    auto init_mid = lsplant::JNI_GetMethodID(env, in_memory_cl_class.get(), "<init>",
                                             "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!init_mid) {
        LOGE("Failed to find InMemoryDexClassLoader constructor.");
        return;
    }

    auto new_cl =
        lsplant::ScopedLocalRef(env, env->NewObject(in_memory_cl_class.get(), init_mid,
                                                    dex_buffer.get(), system_classloader.get()));
    if (env->ExceptionCheck() || !new_cl) {
        LOGE("Failed to create InMemoryDexClassLoader instance.");
        env->ExceptionClear();
        return;
    }

    inject_class_loader_ = env->NewGlobalRef(new_cl.get());
    LOGV("Framework ClassLoader created successfully.");
}

void VectorModule::SetupEntryClass(JNIEnv *env) {
    if (!inject_class_loader_) {
        LOGE("Cannot setup entry class: ClassLoader is null.");
        return;
    }

    const auto &obfs_map = ConfigBridge::GetInstance()->obfuscation_map();
    std::string entry_class_name = obfs_map.at("org.matrix.vector.core.") + "Main";

    auto entry_class = this->FindClassFromLoader(env, inject_class_loader_, entry_class_name);
    if (!entry_class) {
        LOGE("Failed to find entry class '{}' in the loaded DEX.", entry_class_name.c_str());
        return;
    }

    entry_class_ = lsplant::JNI_NewGlobalRef(env, entry_class);
    LOGV("Framework entry class '{}' located.", entry_class_name.c_str());
}

void VectorModule::onLoad(zygisk::Api *api, JNIEnv *env) {
    this->api_ = api;
    this->env_ = env;
    instance_.reset(this);
    ConfigImpl::Init();
    LOGD("Vector Zygisk module loaded");
}

void VectorModule::preAppSpecialize(zygisk::AppSpecializeArgs *args) {
    should_inject_ = false;
    is_manager_app_ = false;
    should_invalidate_ = false;
    {
        std::lock_guard<std::mutex> lock(g_hooks_mutex);
        g_art_hooks.clear();
        g_record_hooks = false;
    }

    if (args->uid == kHostPackageUid) {
        lsplant::JUTFString nice_name_str(env_, args->nice_name);
        if (nice_name_str.get() == std::string(kManagerPackageName)) {
            LOGI("Manager app detected. Granting internet permissions.");
            is_manager_app_ = true;

            int original_gids_count = env_->GetArrayLength(args->gids);
            jintArray new_gids = env_->NewIntArray(original_gids_count + 1);
            if (env_->ExceptionCheck()) {
                LOGE("Failed to create new GID array for manager.");
                env_->ExceptionClear();
                return;
            }

            jint *gids_array = env_->GetIntArrayElements(args->gids, nullptr);
            env_->SetIntArrayRegion(new_gids, 0, original_gids_count, gids_array);
            env_->ReleaseIntArrayElements(args->gids, gids_array, JNI_ABORT);

            jint inet_gid = GID_INET;
            env_->SetIntArrayRegion(new_gids, original_gids_count, 1, &inet_gid);

            if (original_gids_count > 0) {
                env_->SetIntArrayRegion(args->gids, 0, 1, &inet_gid);
            }

            args->nice_name = env_->NewStringUTF(INJECTED_PACKAGE_NAME);
            args->gids = new_gids;
        }
    }

    IPCBridge::GetInstance().Initialize(env_);
    lsplant::JUTFString nice_name_str(env_, args->nice_name);

    if (!args->app_data_dir) {
        LOGD("Skipping injection for '{}': no app_data_dir.", nice_name_str.get());
        return;
    }

    if (args->is_child_zygote && *args->is_child_zygote) {
        LOGD("Skipping injection for '{}': is a child zygote.", nice_name_str.get());
        return;
    }

    const uid_t app_id = args->uid % PER_USER_RANGE;
    if ((app_id >= FIRST_ISOLATED_UID && app_id <= LAST_ISOLATED_UID) ||
        (app_id >= FIRST_APP_ZYGOTE_ISOLATED_UID && app_id <= LAST_APP_ZYGOTE_ISOLATED_UID) ||
        app_id == SHARED_RELRO_UID) {
        LOGV("Skipping injection for '{}': is an isolated process (UID: {}).", nice_name_str.get(),
             app_id);
        return;
    }

    should_inject_ = true;
    LOGV("Process '{}' (UID: {}) is marked for injection.", nice_name_str.get(), args->uid);

    if (!is_manager_app_) {
        should_invalidate_ = ShouldInvalidate(api_, nice_name_str.get());
        VLOGI("Process '%s' should_invalidate=%d", nice_name_str.get(), should_invalidate_ ? 1 : 0);
    }
}

void VectorModule::postAppSpecialize(const zygisk::AppSpecializeArgs *args) {
    if (!should_inject_) {
        SetAllowUnload(true);
        return;
    }

    if (is_manager_app_) {
        args->nice_name = env_->NewStringUTF(kManagerPackageName);
    }

    lsplant::JUTFString nice_name_str(env_, args->nice_name);
    LOGD("Asking the daemon about '{}'.", nice_name_str.get());

    auto &ipc_bridge = IPCBridge::GetInstance();
    auto binder = ipc_bridge.RequestAppBinder(env_, args->nice_name);
    if (!binder) {
        LOGD("Not injecting '{}': the daemon has no binder for it.", nice_name_str.get());
        SetAllowUnload(true);
        return;
    }

    auto [dex_fd, dex_size] = ipc_bridge.FetchFrameworkDex(env_, binder.get());
    if (dex_fd < 0) {
        LOGE("Failed to fetch framework DEX for '{}'.", nice_name_str.get());
        SetAllowUnload(true);
        return;
    }

    auto obfs_map = ipc_bridge.FetchObfuscationMap(env_, binder.get());
    ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));

    {
        PreloadedDex dex(dex_fd, dex_size);
        this->LoadDex(env_, std::move(dex));
    }
    close(dex_fd);

    {
        std::lock_guard<std::mutex> lock(g_hooks_mutex);
        g_art_hooks.clear();
        g_record_hooks = should_invalidate_;
    }
    this->InitArtHooker(env_, init_info_);
    {
        std::lock_guard<std::mutex> lock(g_hooks_mutex);
        g_record_hooks = false;
        VLOGI("Recorded %zu libart.so inline hooks for '%s'", g_art_hooks.size(),
              nice_name_str.get());
    }

    this->InitHooks(env_);
    this->SetupEntryClass(env_);

    bool entered = this->FindAndCall(
        env_, "forkCommon", "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
        JNI_FALSE, JNI_FALSE, args->nice_name, args->app_data_dir, binder.get(), is_manager_app_);

    if (entered) {
        LOGV("Injected Vector framework into '{}'.", nice_name_str.get());
    } else {
        LOGE("Framework entry failed in '{}'; this process runs without Xposed.",
             nice_name_str.get());
    }

    // LSPosed v2.2.1 "还原内联钩子" behavior: restore libart.so from disk after modules load.
    if (should_invalidate_) {
        CleanupLibArtFromDisk(nice_name_str.get());
    }

    SetAllowUnload(false);
}

void VectorModule::preServerSpecialize(zygisk::ServerSpecializeArgs *args) {
    should_inject_ = true;
    LOGI("System server process detected. Marking for injection.");
    IPCBridge::GetInstance().Initialize(env_);
}

void VectorModule::postServerSpecialize(const zygisk::ServerSpecializeArgs *args) {
    if (!should_inject_) {
        SetAllowUnload(true);
        return;
    }

    LOGD("Attempting injection into system_server.");

    if (__system_property_find("ro.vendor.product.ztename")) {
        auto process_class = lsplant::ScopedLocalRef(env_, env_->FindClass("android/os/Process"));
        if (process_class) {
            auto set_argv0_mid =
                env_->GetStaticMethodID(process_class.get(), "setArgV0", "(Ljava/lang/String;)V");
            auto name_str = lsplant::ScopedLocalRef(env_, env_->NewStringUTF("system_server"));
            if (set_argv0_mid && name_str) {
                env_->CallStaticVoidMethod(process_class.get(), set_argv0_mid, name_str.get());
            }
        }
        if (env_->ExceptionCheck()) {
            env_->ExceptionClear();
        }
    }

    auto &ipc_bridge = IPCBridge::GetInstance();
    bool is_late_inject = (args->runtime_flags & RuntimeFlags::LATE_INJECT) != 0 ||
                          ipc_bridge.IsSystemServerRunning(env_);
    std::string bridgeServiceName = is_late_inject ? "serial_vector" : "serial";
    auto system_binder = ipc_bridge.RequestSystemServerBinder(env_, bridgeServiceName);
    if (!system_binder) {
        LOGE("Failed to get system server IPC binder. Aborting injection.");
        SetAllowUnload(true);
        return;
    }

    auto manager_binder =
        ipc_bridge.RequestManagerBinderFromSystemServer(env_, system_binder.get());
    jobject effective_binder = manager_binder ? manager_binder.get() : system_binder.get();

    auto [dex_fd, dex_size] = ipc_bridge.FetchFrameworkDex(env_, effective_binder);
    if (dex_fd < 0) {
        LOGE("Failed to fetch framework DEX for system_server.");
        SetAllowUnload(true);
        return;
    }

    auto obfs_map = ipc_bridge.FetchObfuscationMap(env_, effective_binder);
    ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));

    {
        PreloadedDex dex(dex_fd, dex_size);
        this->LoadDex(env_, std::move(dex));
    }
    close(dex_fd);

    ipc_bridge.HookBridge(env_);
    this->InitArtHooker(env_, init_info_);
    this->InitHooks(env_);
    this->SetupEntryClass(env_);

    auto system_name = lsplant::ScopedLocalRef(env_, env_->NewStringUTF("system"));
    bool entered = this->FindAndCall(
        env_, "forkCommon", "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
        JNI_TRUE, is_late_inject, system_name.get(), nullptr, manager_binder.get(),
        is_manager_app_);

    if (entered) {
        LOGI("Injected Vector framework into system_server.");
    } else {
        LOGE("Framework entry failed in system_server; it runs without Xposed.");
    }
    SetAllowUnload(false);
}

void VectorModule::SetAllowUnload(bool unload) {
    if (api_ && unload) {
        LOGD("Allowing Zygisk to unload module library.");
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

        if (instance_.release() != nullptr) {
            LOGD("Module context singleton released.");
        }
    } else {
        LOGD("Preventing Zygisk from unloading module library.");
    }
}

}  // namespace vector::native::module

REGISTER_ZYGISK_MODULE(vector::native::module::VectorModule);
REGISTER_ZYGISK_COMPANION(vector::native::module::CompanionHandler);
