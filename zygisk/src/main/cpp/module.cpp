#include <common/config.h>
#include <common/logging.h>
#include <core/context.h>
#include <core/native_api.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>
#include <jni/jni_bridge.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>
#include <zygisk.hpp>

#include "ipc_bridge.h"
#include "inline_cleanup.h"

namespace vector::native::module {

namespace {

std::mutex g_art_hooks_mutex;
std::vector<void *> g_art_hooks;
bool g_record_art_hooks = false;

bool ReadExact(int fd, void *buf, size_t len) {
    auto *p = static_cast<uint8_t *>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

bool WriteExact(int fd, const void *buf, size_t len) {
    const auto *p = static_cast<const uint8_t *>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

std::string TrimWhitespace(std::string_view sv) {
    const auto first = sv.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = sv.find_last_not_of(" \t\r\n");
    return std::string(sv.substr(first, last - first + 1));
}

bool MatchesProcessInFile(const char *path, const std::string &proc_name) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string raw_line;
    while (std::getline(file, raw_line)) {
        auto comment_pos = raw_line.find('#');
        if (comment_pos != std::string::npos) {
            raw_line.erase(comment_pos);
        }
        std::string entry = TrimWhitespace(raw_line);
        if (entry.empty()) continue;

        if (entry == "*" || proc_name == entry) {
            return true;
        }
        // Also match child/service processes of the package (e.g. "com.pkg:remote")
        if (proc_name.size() > entry.size() &&
            proc_name.compare(0, entry.size(), entry) == 0 &&
            proc_name[entry.size()] == ':') {
            return true;
        }
    }
    return false;
}

}  // namespace

void CompanionHandler(int client_fd) {
    uint32_t len = 0;
    if (!ReadExact(client_fd, &len, sizeof(len)) || len == 0 || len > 4096) {
        return;
    }
    std::string proc_name(len, '\0');
    if (!ReadExact(client_fd, proc_name.data(), len)) {
        return;
    }

    static constexpr const char *kConfigPaths[] = {
        "/data/adb/vector/invalidate_inline.txt",
        "/data/adb/lspd/invalidate_inline.txt",
        "/data/adb/modules/zygisk_vector/invalidate_inline.txt",
    };

    uint8_t matched = 0;
    for (const char *path : kConfigPaths) {
        if (MatchesProcessInFile(path, proc_name)) {
            matched = 1;
            break;
        }
    }

    WriteExact(client_fd, &matched, sizeof(matched));
}

// --- Process UID Constants ---
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

    // --- ART Hooker Configuration ---
    const lsplant::InitInfo init_info_{
        .inline_hooker =
            [](auto target, auto replace) {
                void *backup = nullptr;
                if (HookInline(target, replace, &backup) == 0) {
                    std::lock_guard<std::mutex> lock(g_art_hooks_mutex);
                    if (g_record_art_hooks &&
                        std::find(g_art_hooks.begin(), g_art_hooks.end(), target) ==
                            g_art_hooks.end()) {
                        g_art_hooks.push_back(target);
                    }
                    return backup;
                }
                return static_cast<void *>(nullptr);
            },
        .inline_unhooker =
            [](auto target) {
                bool ok = UnhookInline(target) == 0;
                if (ok) {
                    std::lock_guard<std::mutex> lock(g_art_hooks_mutex);
                    std::erase(g_art_hooks, target);
                }
                return ok;
            },
        .art_symbol_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbPrefixFirstAddress(symbol); },
        .generated_class_name = "Vector_",
        .generated_source_name = "Dobby",
    };

    bool should_inject_ = false;
    bool is_manager_app_ = false;
    bool should_cleanup_art_ = false;
    bool should_invalidate_inline_hooks_ = false;
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
    std::string entry_class_name;
    entry_class_name = obfs_map.at("org.matrix.vector.core.") + "Main";

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
    should_cleanup_art_ = false;
    should_invalidate_inline_hooks_ = false;
    {
        std::lock_guard<std::mutex> lock(g_art_hooks_mutex);
        g_art_hooks.clear();
        g_record_art_hooks = false;
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
    should_cleanup_art_ = inline_cleanup::ShouldCleanupProcess(api_, nice_name_str.get());
}

    if (!is_manager_app_ && api_) {
        std::string proc_name = nice_name_str.get() ? nice_name_str.get() : "";
        if (!proc_name.empty()) {
            int companion_fd = api_->connectCompanion();
            if (companion_fd >= 0) {
                auto len = static_cast<uint32_t>(proc_name.size());
                uint8_t matched = 0;
                if (WriteExact(companion_fd, &len, sizeof(len)) &&
                    WriteExact(companion_fd, proc_name.data(), len) &&
                    ReadExact(companion_fd, &matched, sizeof(matched))) {
                    should_invalidate_inline_hooks_ = (matched != 0);
                }
                close(companion_fd);
            } else {
                LOGW("Failed to connect to Zygisk companion for '{}'.", proc_name.c_str());
            }
        }
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

    // Record libart.so inline hooks installed by LSPlant if configured for this app.
    {
        std::lock_guard<std::mutex> lock(g_art_hooks_mutex);
        g_art_hooks.clear();
        g_record_art_hooks = should_invalidate_inline_hooks_;
    }
    this->InitArtHooker(env_, init_info_);
    {
        std::lock_guard<std::mutex> lock(g_art_hooks_mutex);
        g_record_art_hooks = false;
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

    if (should_invalidate_inline_hooks_) {
        std::lock_guard<std::mutex> lock(g_art_hooks_mutex);
        size_t restored = 0;
        for (auto it = g_art_hooks.rbegin(); it != g_art_hooks.rend(); ++it) {
            if (UnhookInline(*it) == 0) {
                ++restored;
            } else {
                LOGW("Failed to restore inline hook at {} in '{}'.", *it, nice_name_str.get());
            }
        }
        LOGI("Invalidated {}/{} libart.so inline hooks for '{}'.", restored, g_art_hooks.size(),
             nice_name_str.get());
        g_art_hooks.clear();
    }

    if (should_cleanup_art_) {
    inline_cleanup::CleanupLibArtFromDisk(nice_name_str.get());
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
        LOGV("Applying ZTE-specific workaround: setting argv[0] to system_server.");
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
            LOGW("Exception occurred during ZTE workaround.");
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
REGISTER_ZYGISK_COMPANION(vector::native::inline_cleanup::CompanionHandler);
REGISTER_ZYGISK_COMPANION(vector::native::module::CompanionHandler);
