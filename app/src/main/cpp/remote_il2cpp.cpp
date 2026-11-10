#include "remote_il2cpp.hpp"
#include "mem.hpp"
#include "remote_call.hpp"
#include "remote_elf.hpp"
#include "ui_log.hpp"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct SoModule {
    std::string path;
    uintptr_t base = 0;
    uintptr_t end = 0;
};

static std::string basename(const std::string &p) {
    const auto s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

static bool skip_lib(const std::string &path) {
    if (path.find("/system/") != std::string::npos) return true;
    if (path.find("/apex/") != std::string::npos) return true;
    if (path.find("/vendor/") != std::string::npos) return true;
    const std::string name = basename(path);
    return name == "libdobby.so" || name == "libTool.so";
}

static void collect_modules(pid_t pid, std::vector<SoModule> &out) {
    out.clear();
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return;

    for (const auto &m : maps) {
        if (m.path.empty() || m.path[0] != '/') continue;
        if (m.path.find(".so") == std::string::npos) continue;
        if (skip_lib(m.path)) continue;
        if (m.fileOff != 0 || m.perms[0] != 'r') continue;

        bool merged = false;
        for (auto &mod : out) {
            if (mod.path == m.path) {
                mod.end = std::max(mod.end, m.end);
                merged = true;
                break;
            }
        }
        if (!merged)
            out.push_back({m.path, m.start, m.end});
    }

    std::sort(out.begin(), out.end(), [](const SoModule &a, const SoModule &b) {
        auto score = [](const std::string &n) {
            if (n.find("logic") != std::string::npos) return 100;
            if (n.find("il2cpp") != std::string::npos) return 95;
            if (n.find("csharp") != std::string::npos) return 90;
            if (n.find("GameAssembly") != std::string::npos) return 85;
            if (n.find("unity") != std::string::npos) return 50;
            return 10;
        };
        return score(basename(a.path)) > score(basename(b.path));
    });
}

static bool resolve_sym(pid_t pid, const SoModule &m, const char *sym, uintptr_t &addr) {
    addr = 0;
    if (elf_remote_sym(pid, m.base, sym, addr)) return true;
    ElfRemote er{};
    if (!elf_remote_bias(pid, m.base, er)) return false;
    return elf_file_sym(m.path.c_str(), er.load_bias, sym, addr);
}

static const char *kIl2Api[] = {
    "il2cpp_domain_get",
    "il2cpp_domain_assembly_open",
    "il2cpp_domain_get_assemblies",
    "il2cpp_class_from_name",
    "il2cpp_assembly_get_image",
    "il2cpp_image_get_class_count",
    "il2cpp_image_get_class",
    "il2cpp_class_get_field_from_name",
    "il2cpp_field_static_get_value",
    "il2cpp_thread_attach",
    "il2cpp_class_get_method_from_name",
    "il2cpp_field_get_offset",
    "il2cpp_runtime_invoke",
};

static bool decode_adrp(uint32_t w, uint64_t pc, int64_t &pageOut) {
    if ((w & 0x9F000000u) != 0x90000000u) return false;
    int64_t immhi = (int64_t)((w >> 5) & 0x7ffffu);
    int64_t immlo = (int64_t)((w >> 29) & 0x3u);
    int64_t imm = (immhi | (immlo << 19)) << 12;
    if (w & (1u << 23)) imm |= 0xFFFFFFFFF0000000ULL;
    pageOut = (int64_t)(pc & ~0xFFFULL) + imm;
    return true;
}

static bool domain_from_getter(pid_t pid, uintptr_t func, uintptr_t &domainOut) {
    domainOut = 0;
    if (!func) return false;
    uint32_t ins[32] = {};
    if (!mem_read(pid, func, ins, sizeof(ins))) return false;

    uint64_t x[31] = {};
    for (int i = 0; i < 28; ++i) {
        const uint32_t w = ins[i];
        const uint32_t w2 = ins[i + 1];
        const uint64_t pc = func + (uint64_t)i * 4;

        int64_t page = 0;
        if (decode_adrp(w, pc, page)) {
            const int rd = (int)(w & 0x1fu);
            if (rd >= 0 && rd < 31) x[rd] = (uint64_t)page;
        }
        if ((w & 0xFFC00000u) == 0x91000000u) {
            const int rd = (int)(w & 0x1fu);
            const int rn = (int)((w >> 5) & 0x1fu);
            const uint64_t imm = (uint64_t)((w >> 10) & 0xFFFu);
            if (rd < 31 && rn < 31) x[rd] = x[rn] + imm;
        }
        if ((w2 & 0xFFC00000u) == 0xF9400000u) {
            const int rd = (int)(w2 & 0x1fu);
            const int rn = (int)((w2 >> 5) & 0x1fu);
            const uint64_t off = (uint64_t)(((w2 >> 10) & 0xFFFu) * 8);
            if (rd < 31 && rn < 31) {
                uintptr_t ptr = 0;
                if (mem_read(pid, (uintptr_t)(x[rn] + off), ptr) && mem_ptr_ok(ptr)) {
                    if (rd == 0) domainOut = ptr;
                    x[rd] = ptr;
                }
            }
        }
        if ((w & 0xFFFFFC1Fu) == 0xD65F0000u && (w & 0x1fu) == 0x1fu) {
            if (domainOut) return true;
            if (mem_ptr_ok(x[0])) {
                domainOut = x[0];
                return true;
            }
        }
    }
    return domainOut != 0;
}

static bool module_like_il2cpp(const SoModule &m) {
    const std::string n = basename(m.path);
    if (n.find("logic") != std::string::npos) return true;
    if (n.find("il2cpp") != std::string::npos) return true;
    if (n.find("csharp") != std::string::npos) return true;
    if (n.find("GameAssembly") != std::string::npos) return true;
    const bool inApp = m.path.find("/data/app/") != std::string::npos ||
                       m.path.find("/data/data/") != std::string::npos ||
                       m.path.find("/data/user/") != std::string::npos;
    return inApp;
}

static bool try_module(pid_t pid, const SoModule &m, RemoteIl2CppInfo &out, int &apiHits) {
    apiHits = 0;
    uintptr_t domainGet = 0;
    if (!resolve_sym(pid, m, "il2cpp_domain_get", domainGet) || !domainGet) return false;

    out.export_domain_get = true;
    out.base = m.base;
    out.end = m.end;
    out.sym_domain_get = domainGet;
    std::snprintf(out.libPath, sizeof(out.libPath), "%s", m.path.c_str());
    std::snprintf(out.libBaseName, sizeof(out.libBaseName), "%s", basename(m.path).c_str());

    for (const char *api : kIl2Api) {
        uintptr_t a = 0;
        if (!resolve_sym(pid, m, api, a) || !a) continue;
        ++apiHits;
        if (std::strcmp(api, "il2cpp_domain_assembly_open") == 0)
            out.sym_domain_assembly_open = a;
        if (std::strcmp(api, "il2cpp_domain_get_assemblies") == 0)
            out.sym_domain_get_assemblies = a;
        if (std::strcmp(api, "il2cpp_class_from_name") == 0)
            out.sym_class_from_name = a;
        if (std::strcmp(api, "il2cpp_assembly_get_image") == 0)
            out.sym_assembly_get_image = a;
        if (std::strcmp(api, "il2cpp_image_get_class_count") == 0)
            out.sym_image_get_class_count = a;
        if (std::strcmp(api, "il2cpp_image_get_class") == 0)
            out.sym_image_get_class = a;
        if (std::strcmp(api, "il2cpp_class_get_field_from_name") == 0)
            out.sym_class_get_field_from_name = a;
        if (std::strcmp(api, "il2cpp_field_static_get_value") == 0)
            out.sym_field_static_get_value = a;
        if (std::strcmp(api, "il2cpp_thread_attach") == 0)
            out.sym_thread_attach = a;
        if (std::strcmp(api, "il2cpp_class_get_method_from_name") == 0)
            out.sym_class_get_method_from_name = a;
        if (std::strcmp(api, "il2cpp_field_get_offset") == 0)
            out.sym_field_get_offset = a;
        if (std::strcmp(api, "il2cpp_runtime_invoke") == 0)
            out.sym_runtime_invoke = a;
    }
    out.export_domain_get_assemblies = out.sym_domain_get_assemblies != 0;
    out.export_class_from_name = out.sym_class_from_name != 0;
    out.export_assembly_get_image = out.sym_assembly_get_image != 0;
    out.export_class_get_field_from_name = out.sym_class_get_field_from_name != 0;
    out.export_field_static_get_value = out.sym_field_static_get_value != 0;
    out.export_thread_attach = out.sym_thread_attach != 0;

    if (domain_from_getter(pid, domainGet, out.domain_ptr)) {
        std::snprintf(out.note, sizeof(out.note),
                      "conRent-style sym resolve: %d APIs, domain*=0x%llx",
                      apiHits, (unsigned long long)out.domain_ptr);
    } else {
        std::snprintf(out.note, sizeof(out.note),
                      "conRent-style sym resolve: %d APIs (domain* decode pending)",
                      apiHits);
    }
    return true;
}

static bool domain_looks_valid(pid_t pid, uintptr_t domain) {
    if (!mem_ptr_ok(domain)) return false;
    uintptr_t words[16] = {};
    if (!mem_read(pid, domain, words, sizeof(words))) return false;
    int ptrLike = 0;
    for (uintptr_t w : words)
        if (mem_ptr_ok(w)) ptrLike++;
    return ptrLike >= 2;
}

static void domain_scan_bss(pid_t pid, const RemoteIl2CppInfo &lib, uintptr_t &domainOut) {
    domainOut = 0;
    if (!lib.base) return;
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return;
    for (const auto &m : maps) {
        if (m.start < lib.base || m.end > lib.end + 0x200000ULL) continue;
        if (m.path.find("liblogic") == std::string::npos && m.fileOff != 0) continue;
        if (m.perms[0] != 'r' || m.perms[1] != 'w') continue;
        const size_t sz = (size_t)(m.end - m.start);
        for (size_t off = 0; off < sz; off += 512 * sizeof(uintptr_t)) {
            uintptr_t cand = 0;
            if (!mem_read(pid, m.start + off, cand)) continue;
            if (!domain_looks_valid(pid, cand)) continue;
            domainOut = cand;
            return;
        }
    }
}

static pid_t g_il2CachedPid = 0;
static RemoteIl2CppInfo g_il2Cached{};

} // namespace

bool remote_il2cpp_prime_domain(pid_t pid, RemoteIl2CppInfo &io) {
    if (!io.sym_domain_get) return false;
    uintptr_t domain = 0;
    char err[160] = {};
    if (!remote_call(pid, io.sym_domain_get, {}, domain, err, sizeof(err))) return false;
    if (!mem_ptr_ok(domain)) return false;
    io.domain_ptr = domain;
    std::snprintf(io.note, sizeof(io.note), "live il2cpp_domain_get -> 0x%llx",
                  (unsigned long long)domain);
    return true;
}

bool remote_refresh_domain_ptr(pid_t pid, RemoteIl2CppInfo &io) {
    if (!io.sym_domain_get) return false;
    if (domain_from_getter(pid, io.sym_domain_get, io.domain_ptr)) {
        std::snprintf(io.note, sizeof(io.note), "domain* decoded @ 0x%llx",
                      (unsigned long long)io.domain_ptr);
        return true;
    }
    uint32_t ins[8] = {};
    mem_read(pid, io.sym_domain_get, ins, sizeof(ins));
    ui_log("[il2cpp] domain_get ins: %08X %08X %08X %08X", ins[0], ins[1], ins[2], ins[3]);
    domain_scan_bss(pid, io, io.domain_ptr);
    if (io.domain_ptr) {
        std::snprintf(io.note, sizeof(io.note), "domain* bss scan @ 0x%llx",
                      (unsigned long long)io.domain_ptr);
        return true;
    }
    return false;
}

void remote_il2cpp_invalidate_cache(pid_t pid) {
    if (g_il2CachedPid == pid) {
        g_il2CachedPid = 0;
        g_il2Cached = RemoteIl2CppInfo{};
    }
}

bool remote_detect_il2cpp(pid_t pid, RemoteIl2CppInfo &out) {
    if (g_il2CachedPid == pid && g_il2Cached.sym_domain_get) {
        out = g_il2Cached;
        if (!out.domain_ptr)
            remote_il2cpp_prime_domain(pid, out);
        if (!out.domain_ptr)
            remote_refresh_domain_ptr(pid, out);
        g_il2Cached = out;
        return true;
    }

    out = RemoteIl2CppInfo{};
    std::vector<SoModule> mods;
    collect_modules(pid, mods);
    if (mods.empty()) {
        std::snprintf(out.note, sizeof(out.note), "no mappable .so in pid %d", (int)pid);
        return false;
    }

    int tried = 0;
    for (const SoModule &m : mods) {
        if (!module_like_il2cpp(m)) continue;
        ++tried;
        int hits = 0;
        if (try_module(pid, m, out, hits)) {
            if (!out.domain_ptr)
                remote_il2cpp_prime_domain(pid, out);
            if (!out.domain_ptr)
                remote_refresh_domain_ptr(pid, out);
            g_il2CachedPid = pid;
            g_il2Cached = out;
            ui_log("[il2cpp] OK lib=%s base=0x%llx domain_get=0x%llx apis=%d",
                   out.libBaseName, (unsigned long long)out.base,
                   (unsigned long long)out.sym_domain_get, hits);
            ui_log("[il2cpp] %s", out.note);
            return true;
        }
    }

    for (const SoModule &m : mods) {
        ++tried;
        int hits = 0;
        if (try_module(pid, m, out, hits)) {
            if (!out.domain_ptr)
                remote_il2cpp_prime_domain(pid, out);
            if (!out.domain_ptr)
                remote_refresh_domain_ptr(pid, out);
            g_il2CachedPid = pid;
            g_il2Cached = out;
            ui_log("[il2cpp] OK (fallback) lib=%s apis=%d", out.libBaseName, hits);
            return true;
        }
    }

    std::snprintf(out.note, sizeof(out.note),
                  "scanned %zu modules (%d tried), no il2cpp_domain_get in dynsym/symtab",
                  mods.size(), tried);
    ui_log("[il2cpp] FAIL %s", out.note);
    if (!mods.empty())
        ui_log("[il2cpp] top map: %s @ 0x%llx", mods[0].path.c_str(),
               (unsigned long long)mods[0].base);
    return false;
}
