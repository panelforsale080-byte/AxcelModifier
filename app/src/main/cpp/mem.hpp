#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

/** Direct kernel syscall — no libc process_vm_readv/process_vm_writev. */
inline ssize_t mem_vm_readv(pid_t pid, const iovec *local, unsigned long liovcnt,
                            const iovec *remote, unsigned long riovcnt, unsigned long flags) {
    return syscall(SYS_process_vm_readv, pid, local, liovcnt, remote, riovcnt, flags);
}

inline ssize_t mem_vm_writev(pid_t pid, const iovec *local, unsigned long liovcnt,
                             const iovec *remote, unsigned long riovcnt, unsigned long flags) {
    return syscall(SYS_process_vm_writev, pid, local, liovcnt, remote, riovcnt, flags);
}

struct Vec3 {
    float x = 0, y = 0, z = 0;
};

struct MapsReg {
    uintptr_t start = 0, end = 0, fileOff = 0;
    char perms[8] = {};
    std::string path;
};

bool mem_maps(pid_t pid, std::vector<MapsReg> &out);
void mem_invalidate_maps_cache(pid_t pid);
bool mem_get_maps(pid_t pid, std::vector<MapsReg> &out);
bool mem_is_readable(pid_t pid, uintptr_t addr, size_t len);

bool mem_read(pid_t pid, uintptr_t addr, void *buf, size_t n);
bool mem_write(pid_t pid, uintptr_t addr, const void *buf, size_t n);

template <typename T>
inline bool mem_read(pid_t pid, uintptr_t addr, T &out) {
    return mem_read(pid, addr, &out, sizeof(T));
}

/** Multi-region read in one process_vm_readv syscall (no ptrace). */
bool mem_read_batch(pid_t pid, const std::vector<std::pair<uintptr_t, size_t>> &reqs,
                    std::vector<std::vector<uint8_t>> &out);

bool mem_ptr_ok(uintptr_t p);
