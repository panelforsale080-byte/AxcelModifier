#pragma once
// User-space external reads: process_vm_readv + /proc maps validation + iovec batches.
#include "mem.hpp"
#include <sys/uio.h>
#include <errno.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace ext_read {

inline bool region_readable(const std::vector<MapsReg> &maps, uintptr_t addr, size_t len) {
    if (!addr || !len) return false;
    const uintptr_t end = addr + len;
    if (end < addr) return false;
    auto it = std::upper_bound(
        maps.begin(), maps.end(), addr,
        [](uintptr_t a, const MapsReg &r) { return a < r.start; });
    if (it == maps.begin()) return false;
    --it;
    return it->perms[0] == 'r' && addr >= it->start && end <= it->end;
}

inline ssize_t read_batch(pid_t pid, const std::vector<std::pair<uintptr_t, size_t>> &reqs,
                          std::vector<std::vector<uint8_t>> &out) {
    if (!pid || reqs.empty()) return 0;
    std::vector<iovec> local(reqs.size());
    std::vector<iovec> remote(reqs.size());
    out.resize(reqs.size());
    for (size_t i = 0; i < reqs.size(); ++i) {
        out[i].resize(reqs[i].second);
        local[i].iov_base = out[i].data();
        local[i].iov_len = reqs[i].second;
        remote[i].iov_base = reinterpret_cast<void *>(reqs[i].first);
        remote[i].iov_len = reqs[i].second;
    }
    const ssize_t total =
        mem_vm_readv(pid, local.data(), local.size(), remote.data(), remote.size(), 0);
    if (total < 0 && errno != EFAULT) return -1;
    return total;
}

inline bool read_mem(pid_t pid, std::vector<MapsReg> &maps, uintptr_t addr, void *dst,
                     size_t len) {
    if (!pid || !addr || !dst || !len) return false;
    if (!region_readable(maps, addr, len)) {
        if (!mem_maps(pid, maps)) return false;
        if (!region_readable(maps, addr, len)) return false;
    }
    std::vector<std::pair<uintptr_t, size_t>> req = {{addr, len}};
    std::vector<std::vector<uint8_t>> buf;
    const ssize_t n = read_batch(pid, req, buf);
    if (n != (ssize_t)len || buf.empty()) return false;
    std::memcpy(dst, buf[0].data(), len);
    return true;
}

template <class T>
inline bool read_t(pid_t pid, std::vector<MapsReg> &maps, uintptr_t addr, T &out) {
    return read_mem(pid, maps, addr, &out, sizeof(T));
}

} // namespace ext_read
