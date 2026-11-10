#include "mem.hpp"
#include "external_esp_read.hpp"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <mutex>

static std::mutex g_mapsMu;
static pid_t g_mapsPid = 0;
static std::vector<MapsReg> g_mapsCache;

bool mem_ptr_ok(uintptr_t p) {
    return p >= 0x10000ULL && p < 0x800000000000ULL && ((p & 7ULL) == 0);
}

bool mem_maps(pid_t pid, std::vector<MapsReg> &out) {
    out.clear();
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) return false;
    std::string line;
    while (std::getline(maps, line)) {
        MapsReg r{};
        char path[512] = {};
        unsigned long off = 0;
        if (std::sscanf(line.c_str(), "%lx-%lx %7s %lx %*s %*s %511[^\n]", &r.start, &r.end,
                        r.perms, &off, path) < 4)
            continue;
        r.fileOff = off;
        r.path = path;
        while (!r.path.empty() && r.path[0] == ' ') r.path.erase(0, 1);
        out.push_back(r);
    }
    std::sort(out.begin(), out.end(),
              [](const MapsReg &a, const MapsReg &b) { return a.start < b.start; });
    return !out.empty();
}

void mem_invalidate_maps_cache(pid_t pid) {
    std::lock_guard<std::mutex> lock(g_mapsMu);
    if (pid <= 0 || g_mapsPid == pid) {
        g_mapsPid = 0;
        g_mapsCache.clear();
    }
}

bool mem_get_maps(pid_t pid, std::vector<MapsReg> &out) {
    if (pid <= 0) return false;
    std::lock_guard<std::mutex> lock(g_mapsMu);
    if (g_mapsPid != pid || g_mapsCache.empty()) {
        g_mapsCache.clear();
        if (!mem_maps(pid, g_mapsCache)) return false;
        g_mapsPid = pid;
    }
    out = g_mapsCache;
    return true;
}

bool mem_is_readable(pid_t pid, uintptr_t addr, size_t len) {
    std::vector<MapsReg> maps;
    if (!mem_get_maps(pid, maps)) return false;
    return ext_read::region_readable(maps, addr, len);
}

bool mem_read_batch(pid_t pid, const std::vector<std::pair<uintptr_t, size_t>> &reqs,
                    std::vector<std::vector<uint8_t>> &out) {
    if (!pid || reqs.empty()) return false;
    std::vector<MapsReg> maps;
    if (!mem_get_maps(pid, maps)) return false;
    for (const auto &r : reqs) {
        if (!ext_read::region_readable(maps, r.first, r.second)) {
            mem_invalidate_maps_cache(pid);
            if (!mem_get_maps(pid, maps)) return false;
            if (!ext_read::region_readable(maps, r.first, r.second)) return false;
        }
    }
    const ssize_t n = ext_read::read_batch(pid, reqs, out);
    if (n <= 0) return false;
    size_t need = 0;
    for (const auto &r : reqs) need += r.second;
    return (size_t)n >= need;
}

bool mem_read(pid_t pid, uintptr_t addr, void *buf, size_t n) {
    if (!pid || !addr || !buf || !n) return false;
    iovec local{(void *)buf, n};
    iovec remote{(void *)addr, n};
    const ssize_t ret = mem_vm_readv(pid, &local, 1, &remote, 1, 0);
    return ret == (ssize_t)n;
}

bool mem_write(pid_t pid, uintptr_t addr, const void *buf, size_t n) {
    if (!pid || !addr || !buf || !n) return false;
    iovec local{(void *)buf, n};
    iovec remote{(void *)addr, n};
    return mem_vm_writev(pid, &local, 1, &remote, 1, 0) == (ssize_t)n;
}
