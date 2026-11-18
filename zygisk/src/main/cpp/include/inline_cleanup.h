#pragma once

#include <android/log.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <zygisk.hpp>

#define VLOGI(...) __android_log_print(ANDROID_LOG_INFO, "VectorInline", __VA_ARGS__)
#define VLOGW(...) __android_log_print(ANDROID_LOG_WARN, "VectorInline", __VA_ARGS__)

namespace vector::native::inline_cleanup {

#if defined(__LP64__)
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Phdr = Elf64_Phdr;
#else
using Elf_Ehdr = Elf32_Ehdr;
using Elf_Phdr = Elf32_Phdr;
#endif

inline bool ReadExact(int fd, void *buf, size_t len) {
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

inline bool WriteExact(int fd, const void *buf, size_t len) {
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

inline std::string Trim(std::string_view sv) {
    const auto first = sv.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = sv.find_last_not_of(" \t\r\n");
    return std::string(sv.substr(first, last - first + 1));
}

inline bool MatchesStream(std::istream &stream, const std::string &proc) {
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

inline bool MatchesModuleDirFile(int dir_fd, const std::string &proc) {
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

inline void CompanionHandler(int client_fd) {
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

inline bool ShouldCleanupProcess(zygisk::Api *api, const char *nice_name) {
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

inline void CleanupLibArtFromDisk(const char *proc_name) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return;

    std::string art_path;
    uintptr_t ref_start = 0;
    uintptr_t ref_offset = 0;
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
        if (path.ends_with("/libart.so")) {
            art_path = path;
            ref_start = start;
            ref_offset = offset;
            found = true;
            if (offset == 0) break;
        }
    }
    if (!found) {
        VLOGW("libart.so not found in maps for %s", proc_name);
        return;
    }

    int fd = open(art_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        VLOGW("Failed to open %s: errno=%d", art_path.c_str(), errno);
        return;
    }

    Elf_Ehdr ehdr{};
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        close(fd);
        return;
    }

    std::vector<Elf_Phdr> phdrs(ehdr.e_phnum);
    ssize_t ph_bytes = static_cast<ssize_t>(phdrs.size() * sizeof(Elf_Phdr));
    if (pread(fd, phdrs.data(), ph_bytes, static_cast<off_t>(ehdr.e_phoff)) != ph_bytes) {
        close(fd);
        return;
    }

    const size_t page_sz = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t load_bias = 0;
    bool bias_ok = false;
    for (const auto &ph : phdrs) {
        if (ph.p_type == PT_LOAD && ref_offset >= ph.p_offset &&
            ref_offset < ph.p_offset + ph.p_filesz) {
            load_bias = ref_start - (ph.p_vaddr + (ref_offset - ph.p_offset));
            bias_ok = true;
            break;
        }
    }
    if (!bias_ok) {
        close(fd);
        VLOGW("Failed to compute load_bias for %s", proc_name);
        return;
    }

    size_t cleaned = 0;
    for (const auto &ph : phdrs) {
        if (ph.p_type != PT_LOAD || (ph.p_flags & PF_X) == 0 || ph.p_filesz == 0) continue;

        uintptr_t seg_start = (load_bias + ph.p_vaddr) & ~(page_sz - 1);
        uintptr_t seg_end = (load_bias + ph.p_vaddr + ph.p_filesz + page_sz - 1) & ~(page_sz - 1);
        off_t file_off = static_cast<off_t>(ph.p_offset & ~(page_sz - 1));
        size_t map_len = seg_end - seg_start;

        void *res = mmap(reinterpret_cast<void *>(seg_start), map_len, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE | MAP_FIXED, fd, file_off);
        if (res != MAP_FAILED) {
            __builtin___clear_cache(reinterpret_cast<char *>(seg_start),
                                    reinterpret_cast<char *>(seg_end));
            ++cleaned;
        } else {
            VLOGW("mmap restore failed at %" PRIxPTR " errno=%d", seg_start, errno);
        }
    }

    close(fd);
    VLOGI("Cleaned %zu executable segment(s) of libart.so from disk for '%s'", cleaned, proc_name);
}

}  // namespace vector::native::inline_cleanup
