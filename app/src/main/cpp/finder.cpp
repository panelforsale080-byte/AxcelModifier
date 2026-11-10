#include "finder.hpp"
#include "mem.hpp"
#include "remote_call.hpp"
#include "remote_elf.hpp"
#include "remote_il2cpp.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

struct ClassRec {
    uintptr_t klass = 0;
    std::string full;
    std::string image;
};

struct Images {
    uintptr_t assemblyCSharp = 0;
    uintptr_t unityCore = 0;
    std::vector<uintptr_t> all;
};

struct State {
    pid_t pid = 0;
    RemoteIl2CppInfo il2{};
    uintptr_t domain = 0;
    Images images{};
    uintptr_t sym_class_get_fields = 0;
    uintptr_t sym_field_get_name = 0;
    uintptr_t sym_class_get_name = 0;
    uintptr_t sym_class_get_namespace = 0;
    uintptr_t sym_class_get_type = 0;
    uintptr_t sym_type_get_name = 0;
    uintptr_t sym_free = 0;
    uintptr_t sym_image_get_name = 0;
    uintptr_t sym_class_get_parent = 0;
    uintptr_t sym_class_get_flags = 0;
    uintptr_t sym_class_get_methods = 0;
    uintptr_t sym_method_get_name = 0;
    bool ready = false;
    bool indexReady = false;
    size_t indexImages = 0;
    std::vector<ClassRec> index;
};

State g;

int put_text(char *out, size_t cap, const std::string &s) {
    if (!out || cap == 0) return 0;
    std::snprintf(out, cap, "%s", s.c_str());
    return (int)std::strlen(out);
}

uintptr_t scratch_cstr(RemoteSession &s, pid_t pid, int slot, const char *lit) {
    if (!lit) lit = "";
    const size_t n = std::strlen(lit) + 1;
    const uintptr_t p = remote_session_scratch(s, slot, n);
    if (!p || !mem_write(pid, p, lit, n)) return 0;
    return p;
}

bool read_remote_cstr(pid_t pid, uintptr_t p, char *buf, size_t n) {
    if (!buf || n < 2) return false;
    buf[0] = '\0';
    if (!mem_ptr_ok(p)) return false;
    size_t filled = 0;
    const size_t limit = std::min(n - 1, (size_t)160);
    while (filled < limit) {
        const uintptr_t addr = p + filled;
        size_t chunk = limit - filled;
        const uintptr_t pageLeft = 0x1000u - (addr & 0xFFFu);
        if (chunk > pageLeft) chunk = (size_t)pageLeft;
        if (chunk > 32) chunk = 32;
        if (!chunk || !mem_read(pid, addr, buf + filled, chunk)) {
            if (!filled) return false;
            break;
        }
        for (size_t i = 0; i < chunk; ++i) {
            const unsigned char c = (unsigned char)buf[filled + i];
            if (c == '\0') {
                buf[filled + i] = '\0';
                return filled + i > 0;
            }
            if (c < 0x20 || c > 0x7e) {
                buf[0] = '\0';
                return false;
            }
        }
        filled += chunk;
    }
    buf[0] = '\0';
    return false;
}

bool klass_name_at(pid_t pid, uintptr_t klass, char *buf, size_t n) {
    for (uintptr_t off : {0x10u, 0x18u, 0x08u}) {
        uintptr_t p = 0;
        if (!mem_read(pid, klass + off, p)) continue;
        if (read_remote_cstr(pid, p, buf, n)) return true;
    }
    return false;
}

void split_name(const std::string &full, std::string &ns, std::string &cls) {
    const auto dot = full.find_last_of('.');
    if (dot == std::string::npos) {
        ns.clear();
        cls = full;
    } else {
        ns = full.substr(0, dot);
        cls = full.substr(dot + 1);
    }
}

uintptr_t class_from_name(RemoteSession &s, uintptr_t image, const std::string &ns,
                          const std::string &cls) {
    if (!image || !g.il2.sym_class_from_name) return 0;
    const uintptr_t nsPtr = scratch_cstr(s, g.pid, 5, ns.c_str());
    const uintptr_t namePtr = scratch_cstr(s, g.pid, 6, cls.c_str());
    if (!nsPtr || !namePtr) return 0;
    uintptr_t klass = 0;
    if (!remote_session_call(s, g.il2.sym_class_from_name, {image, nsPtr, namePtr}, klass))
        return 0;
    return mem_ptr_ok(klass) ? klass : 0;
}

bool eq_ci(const char *a, const std::string &b) {
    if (!a) return false;
    const size_t n = std::strlen(a);
    if (n != b.size()) return false;
    for (size_t i = 0; i < n; ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
}

bool read_ns_name(pid_t pid, uintptr_t klass, char *ns, size_t nsn, char *name, size_t namen) {
    struct Pair {
        uintptr_t nameOff;
        uintptr_t nsOff;
    };
    static const Pair kPairs[] = {{0x10, 0x18}, {0x18, 0x10}, {0x08, 0x10}};
    for (const Pair &p : kPairs) {
        name[0] = '\0';
        ns[0] = '\0';
        uintptr_t np = 0;
        if (!mem_read(pid, klass + p.nameOff, np)) continue;
        if (!read_remote_cstr(pid, np, name, namen)) continue;
        uintptr_t sp = 0;
        if (mem_read(pid, klass + p.nsOff, sp)) read_remote_cstr(pid, sp, ns, nsn);
        return true;
    }
    return false;
}

bool call_cstr(RemoteSession &s, uintptr_t fn, uintptr_t arg, char *buf, size_t n);

bool contains_ci(const std::string &hay, const std::string &needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower((unsigned char)hay[i + j]) != std::tolower((unsigned char)needle[j])) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

std::string short_type_name(const std::string &full) {
    size_t cut = full.find_last_of(".+/");
    std::string s = cut == std::string::npos ? full : full.substr(cut + 1);
    const size_t comma = s.find(',');
    if (comma != std::string::npos) s = s.substr(0, comma);
    return s;
}

int type_rank(const std::string &typeName, const std::string &query) {
    if (typeName.empty() || query.empty()) return 0;
    if (eq_ci(typeName.c_str(), query)) return 3;
    if (eq_ci(short_type_name(typeName).c_str(), query)) return 2;
    if (contains_ci(typeName, query)) return 1;
    return 0;
}

std::string type_full_name(RemoteSession &s, uintptr_t klass) {
    char buf[192] = {};
    if (g.sym_class_get_type && g.sym_type_get_name) {
        uintptr_t type = 0;
        if (remote_session_call(s, g.sym_class_get_type, {klass}, type) && type) {
            uintptr_t namePtr = 0;
            if (remote_session_call(s, g.sym_type_get_name, {type}, namePtr) && mem_ptr_ok(namePtr)) {
                read_remote_cstr(g.pid, namePtr, buf, sizeof(buf));
                if (g.sym_free) {
                    uintptr_t ignored = 0;
                    remote_session_call(s, g.sym_free, {namePtr}, ignored);
                }
            }
        }
    }
    if (!buf[0]) {
        char name[96] = {};
        char ns[96] = {};
        if (g.sym_class_get_name)
            call_cstr(s, g.sym_class_get_name, klass, name, sizeof(name));
        if (!name[0]) klass_name_at(g.pid, klass, name, sizeof(name));
        if (g.sym_class_get_namespace)
            call_cstr(s, g.sym_class_get_namespace, klass, ns, sizeof(ns));
        if (name[0]) {
            if (ns[0])
                std::snprintf(buf, sizeof(buf), "%s.%s", ns, name);
            else
                std::snprintf(buf, sizeof(buf), "%s", name);
        }
    }
    return buf;
}

struct Hit {
    uintptr_t klass = 0;
    std::string typeName;
    std::string image;
    int rank = 0;
};

struct Found {
    std::vector<Hit> hits;
    size_t scanned = 0;
    size_t images = 0;
};

void keep_hit(Found &found, Hit hit) {
    if (!mem_ptr_ok(hit.klass) || hit.rank <= 0) return;
    for (Hit &old : found.hits) {
        if (old.klass == hit.klass) {
            if (hit.rank > old.rank) old = std::move(hit);
            return;
        }
    }
    size_t same = 0;
    for (const Hit &old : found.hits)
        if (old.rank == hit.rank) ++same;
    if (hit.rank >= 2 && same >= 16) return;
    if (hit.rank == 1 && same >= 24) return;
    found.hits.push_back(std::move(hit));
}

std::string image_name(RemoteSession &s, uintptr_t image) {
    char buf[128] = {};
    if (g.sym_image_get_name) call_cstr(s, g.sym_image_get_name, image, buf, sizeof(buf));
    return buf;
}

bool pointer_is_cstr(uintptr_t p, const char *expect) {
    char buf[128] = {};
    if (!expect || !expect[0] || !read_remote_cstr(g.pid, p, buf, sizeof(buf))) return false;
    return std::strcmp(buf, expect) == 0;
}

bool learn_name_offs(RemoteSession &s, uintptr_t klass, uintptr_t &nameOff, uintptr_t &nsOff) {
    if (!klass || !g.sym_class_get_name) return false;
    char expect[96] = {};
    char nsExpect[96] = {};
    if (!call_cstr(s, g.sym_class_get_name, klass, expect, sizeof(expect))) return false;
    const bool haveNs =
        g.sym_class_get_namespace &&
        call_cstr(s, g.sym_class_get_namespace, klass, nsExpect, sizeof(nsExpect));
    bool nameFound = false;
    for (uintptr_t off = 0; off <= 0x80; off += 8) {
        uintptr_t p = 0;
        if (!mem_read(g.pid, klass + off, p)) continue;
        if (!nameFound && pointer_is_cstr(p, expect)) {
            nameOff = off;
            nameFound = true;
        }
        if (haveNs && nsExpect[0] && pointer_is_cstr(p, nsExpect)) nsOff = off;
    }
    return nameFound;
}

bool read_indexed_name(RemoteSession &s, uintptr_t klass, uintptr_t nameOff, uintptr_t nsOff,
                       bool apiNames, std::string &full) {
    char name[128] = {};
    char ns[128] = {};
    bool fromApi = apiNames;
    if (!apiNames) {
        uintptr_t np = 0;
        if (mem_read(g.pid, klass + nameOff, np))
            read_remote_cstr(g.pid, np, name, sizeof(name));
        if (name[0] && nsOff) {
            uintptr_t sp = 0;
            if (mem_read(g.pid, klass + nsOff, sp)) read_remote_cstr(g.pid, sp, ns, sizeof(ns));
        }
    }
    if (!name[0] && g.sym_class_get_name) {
        fromApi = call_cstr(s, g.sym_class_get_name, klass, name, sizeof(name));
    }
    if (!name[0]) return false;
    if (fromApi && !ns[0] && g.sym_class_get_namespace)
        call_cstr(s, g.sym_class_get_namespace, klass, ns, sizeof(ns));
    full = ns[0] ? std::string(ns) + "." + name : std::string(name);
    return true;
}

void ensure_index(RemoteSession &s) {
    if (g.indexReady || !g.il2.sym_image_get_class || !g.il2.sym_image_get_class_count) return;
    g.index.clear();
    g.indexImages = 0;
    uintptr_t nameOff = 0x10;
    uintptr_t nsOff = 0;
    bool apiNames = true;
    int probes = 0;
    for (uintptr_t image : g.images.all) {
        if (!apiNames || probes >= 6) break;
        uintptr_t count = 0;
        if (!remote_session_call(s, g.il2.sym_image_get_class_count, {image}, count)) continue;
        const size_t n = std::min((size_t)count, (size_t)6);
        for (size_t i = 0; i < n && probes < 6; ++i) {
            uintptr_t klass = 0;
            if (!remote_session_call(s, g.il2.sym_image_get_class, {image, i}, klass) || !klass)
                continue;
            ++probes;
            if (learn_name_offs(s, klass, nameOff, nsOff)) apiNames = false;
        }
    }
    for (uintptr_t image : g.images.all) {
        uintptr_t count = 0;
        if (!remote_session_call(s, g.il2.sym_image_get_class_count, {image}, count)) continue;
        const size_t n = (size_t)count;
        if (n == 0 || n > 250000) continue;
        ++g.indexImages;
        const std::string iname = image_name(s, image);
        for (size_t i = 0; i < n; ++i) {
            uintptr_t klass = 0;
            if (!remote_session_call(s, g.il2.sym_image_get_class, {image, i}, klass) || !klass)
                continue;
            std::string full;
            if (!read_indexed_name(s, klass, nameOff, nsOff, apiNames, full)) continue;
            g.index.push_back(ClassRec{klass, std::move(full), iname});
        }
    }
    g.indexReady = true;
}

Found find_classes(RemoteSession &s, const char *fullName) {
    Found found;
    const std::string query = fullName ? fullName : "";
    if (query.empty()) return found;
    std::string ns, cls;
    split_name(query, ns, cls);
    if (cls.empty()) return found;
    if (!g.indexReady) ensure_index(s);
    found.scanned = g.index.size();
    found.images = g.indexImages;
    for (const ClassRec &rec : g.index) {
        const int rank = type_rank(rec.full, query);
        if (!rank) continue;
        keep_hit(found, Hit{rec.klass, rec.full, rec.image, rank});
    }
    std::sort(found.hits.begin(), found.hits.end(), [](const Hit &a, const Hit &b) {
        if (a.rank != b.rank) return a.rank > b.rank;
        return a.typeName < b.typeName;
    });
    return found;
}

void resolve_extra_syms() {
    uintptr_t bias = 0;
    if (!elf_file_map_bias(g.il2.libPath, g.il2.base, bias)) bias = g.il2.base;
    auto one = [&](const char *name) {
        uintptr_t a = 0;
        if (!elf_file_sym(g.il2.libPath, bias, name, a)) a = 0;
        return a;
    };
    g.sym_class_get_fields = one("il2cpp_class_get_fields");
    g.sym_field_get_name = one("il2cpp_field_get_name");
    g.sym_class_get_name = one("il2cpp_class_get_name");
    g.sym_class_get_namespace = one("il2cpp_class_get_namespace");
    g.sym_class_get_type = one("il2cpp_class_get_type");
    g.sym_type_get_name = one("il2cpp_type_get_name");
    g.sym_free = one("il2cpp_free");
    g.sym_image_get_name = one("il2cpp_image_get_name");
    g.sym_class_get_parent = one("il2cpp_class_get_parent");
    g.sym_class_get_flags = one("il2cpp_class_get_flags");
    g.sym_class_get_methods = one("il2cpp_class_get_methods");
    g.sym_method_get_name = one("il2cpp_method_get_name");
}

bool call_cstr(RemoteSession &s, uintptr_t fn, uintptr_t arg, char *buf, size_t n) {
    if (!fn) return false;
    uintptr_t p = 0;
    if (!remote_session_call(s, fn, {arg}, p)) return false;
    return read_remote_cstr(g.pid, p, buf, n);
}

void append_fields(RemoteSession &s, uintptr_t klass, std::string &out) {
    if (!g.sym_class_get_fields || !g.il2.sym_field_get_offset) {
        out += "\t// il2cpp_class_get_fields not exported\n";
        return;
    }
    const uintptr_t iterSlot = remote_session_scratch(s, 8, sizeof(uintptr_t));
    if (!iterSlot) return;
    uintptr_t zero = 0;
    mem_write(g.pid, iterSlot, &zero, sizeof(zero));
    int shown = 0;
    for (int i = 0; i < 800 && shown < 400; ++i) {
        uintptr_t field = 0;
        if (!remote_session_call(s, g.sym_class_get_fields, {klass, iterSlot}, field) ||
            !mem_ptr_ok(field))
            break;
        char name[80] = {};
        if (g.sym_field_get_name) call_cstr(s, g.sym_field_get_name, field, name, sizeof(name));
        uintptr_t off = 0;
        remote_session_call(s, g.il2.sym_field_get_offset, {field}, off);
        char line[120];
        std::snprintf(line, sizeof(line), "\t%s; // Offset: 0x%llx\n", name[0] ? name : "?",
                      (unsigned long long)off);
        out += line;
        ++shown;
    }
    if (shown == 0) out += "\t// (none)\n";
}

void append_methods(RemoteSession &s, uintptr_t klass, std::string &out) {
    out += "\n\t// Methods\n";
    if (!g.sym_class_get_methods) {
        out += "\t// il2cpp_class_get_methods not exported\n";
        return;
    }
    const uintptr_t iterSlot = remote_session_scratch(s, 9, sizeof(uintptr_t));
    if (!iterSlot) return;
    uintptr_t zero = 0;
    mem_write(g.pid, iterSlot, &zero, sizeof(zero));
    int shown = 0;
    for (int i = 0; i < 400 && shown < 120; ++i) {
        uintptr_t method = 0;
        if (!remote_session_call(s, g.sym_class_get_methods, {klass, iterSlot}, method) ||
            !mem_ptr_ok(method))
            break;
        char name[96] = {};
        if (g.sym_method_get_name) call_cstr(s, g.sym_method_get_name, method, name, sizeof(name));
        uintptr_t fn = 0;
        if (!mem_read(g.pid, method, fn) || !mem_ptr_ok(fn))
            mem_read(g.pid, method + 8, fn);
        const bool inLib = g.il2.base && g.il2.end > g.il2.base && fn >= g.il2.base && fn < g.il2.end;
        const uintptr_t rva = inLib ? fn - g.il2.base : 0;
        char line[320];
        if (inLib) {
            std::snprintf(line, sizeof(line),
                          "\t// Offset: 0x%llx\n\t// Address: 0x%llx\n\t// base+0x%llx\n\t%s() { }\n",
                          (unsigned long long)rva, (unsigned long long)fn, (unsigned long long)rva,
                          name[0] ? name : "?");
        } else if (mem_ptr_ok(fn)) {
            std::snprintf(line, sizeof(line),
                          "\t// Address: 0x%llx\n\t// base 0x%llx\n\t%s() { }\n",
                          (unsigned long long)fn, (unsigned long long)g.il2.base,
                          name[0] ? name : "?");
        } else {
            std::snprintf(line, sizeof(line), "\t// no pointer\n\t%s() { }\n", name[0] ? name : "?");
        }
        out += line;
        ++shown;
    }
    if (shown == 0) out += "\t// (none)\n";
}

std::string describe(RemoteSession &s, uintptr_t klass, const std::string &knownType) {
    std::string typeName = knownType.empty() ? type_full_name(s, klass) : knownType;
    char ns[128] = {};
    char name[128] = {};
    if (g.sym_class_get_namespace)
        call_cstr(s, g.sym_class_get_namespace, klass, ns, sizeof(ns));
    if (g.sym_class_get_name)
        call_cstr(s, g.sym_class_get_name, klass, name, sizeof(name));
    if (!name[0]) {
        const std::string shortName = short_type_name(typeName);
        std::snprintf(name, sizeof(name), "%s", shortName.c_str());
    }
    if (!ns[0]) {
        const auto dot = typeName.find_last_of('.');
        if (dot != std::string::npos)
            std::snprintf(ns, sizeof(ns), "%s", typeName.substr(0, dot).c_str());
    }
    if (!name[0] && typeName.empty()) return "address is not an Il2CppClass\n";

    uintptr_t flags = 0;
    if (g.sym_class_get_flags) remote_session_call(s, g.sym_class_get_flags, {klass}, flags);
    flags &= 0xffffffffu;
    const bool isStatic = (flags & 0x80u) && (flags & 0x100u);
    const bool isSealed = (flags & 0x100u) && !isStatic;
    const bool isAbstract = (flags & 0x80u) && !isStatic;
    const bool isIface = (flags & 0x20u) != 0;
    const unsigned vis = (unsigned)(flags & 7u);

    uintptr_t parent = 0;
    std::string parentName;
    if (g.sym_class_get_parent &&
        remote_session_call(s, g.sym_class_get_parent, {klass}, parent) && mem_ptr_ok(parent)) {
        parentName = short_type_name(type_full_name(s, parent));
        if (parentName == "Object" || parentName == "ValueType" || parentName == "Enum")
            parentName.clear();
    }

    std::string out;
    char line[384];
    std::snprintf(line, sizeof(line), "// Namespace: %s\n", ns[0] ? ns : "");
    out += line;
    if (isSealed) out += "// [Sealed]\n";
    std::string decl;
    if (vis == 1 || vis == 2) decl += "public ";
    else if (vis == 0 || vis == 5 || vis == 6) decl += "internal ";
    else if (vis == 3) decl += "private ";
    else if (vis == 4) decl += "protected ";
    if (isStatic) decl += "static ";
    else if (isAbstract && !isIface) decl += "abstract ";
    else if (isSealed) decl += "sealed ";
    decl += isIface ? "interface " : "class ";
    decl += name[0] ? name : "?";
    if (!parentName.empty()) {
        decl += " : ";
        decl += parentName;
    }
    out += decl;
    out += "\n";
    std::snprintf(line, sizeof(line),
                  "// klass 0x%llx\n// parent %s 0x%llx\n// lib %s base 0x%llx\n{\n\t// Fields\n",
                  (unsigned long long)klass, parentName.empty() ? "-" : parentName.c_str(),
                  (unsigned long long)parent, g.il2.libBaseName, (unsigned long long)g.il2.base);
    out += line;
    append_fields(s, klass, out);
    append_methods(s, klass, out);
    out += "}\n";
    return out;
}

std::string search_by_address(RemoteSession &s, uintptr_t raw) {
    const uintptr_t base = g.il2.base;
    const uintptr_t span = (g.il2.end > base) ? (g.il2.end - base) : 0;
    uintptr_t addr = raw;
    bool fromBase = false;
    if (base && raw < 0x100000000ULL && (span == 0 || raw < span)) {
        addr = base + raw;
        fromBase = true;
    }
    char math[192];
    if (fromBase) {
        std::snprintf(math, sizeof(math), "il2cpp + 0x%llx = 0x%llx\n",
                      (unsigned long long)raw, (unsigned long long)addr);
    } else if (base && addr >= base && span && addr < base + span) {
        std::snprintf(math, sizeof(math), "il2cpp + 0x%llx = 0x%llx\n",
                      (unsigned long long)(addr - base), (unsigned long long)addr);
    } else {
        std::snprintf(math, sizeof(math), "address 0x%llx\nlib base 0x%llx\n",
                      (unsigned long long)addr, (unsigned long long)base);
    }
    std::string body = describe(s, addr, "");
    if (body.find("not an Il2CppClass") != std::string::npos) {
        uintptr_t pointed = 0;
        if (mem_read(g.pid, addr, pointed) && mem_ptr_ok(pointed)) {
            std::string nested = describe(s, pointed, "");
            if (nested.find("not an Il2CppClass") == std::string::npos) {
                char hop[96];
                std::snprintf(hop, sizeof(hop), "pointer -> klass 0x%llx\n",
                              (unsigned long long)pointed);
                return std::string(math) + hop + nested;
            }
        }
    }
    return std::string(math) + body;
}

bool looks_like_offset(const std::string &q) {
    if (q.size() < 3) return false;
    size_t i = 0;
    if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) i = 2;
    if (i >= q.size()) return false;
    for (; i < q.size(); ++i)
        if (!std::isxdigit((unsigned char)q[i])) return false;
    return true;
}

bool open_session(RemoteSession &s, std::string &err) {
    if (!remote_session_begin(g.pid, s)) {
        err = s.err[0] ? s.err : "ptrace attach failed";
        return false;
    }
    if (g.il2.sym_thread_attach && g.domain) {
        uintptr_t thr = 0;
        remote_session_call(s, g.il2.sym_thread_attach, {g.domain}, thr);
    }
    return true;
}

void collect_images(RemoteSession &s) {
    g.images = {};
    if (g.il2.sym_domain_assembly_open && g.domain) {
        static const char *kCs[] = {"Assembly-CSharp", "Assembly-CSharp.dll",
                                    "Assembly-CSharp-firstpass.dll"};
        for (const char *name : kCs) {
            if (g.images.assemblyCSharp) break;
            const uintptr_t np = scratch_cstr(s, g.pid, 3, name);
            uintptr_t as = 0, img = 0;
            if (np && remote_session_call(s, g.il2.sym_domain_assembly_open, {g.domain, np}, as) &&
                as && remote_session_call(s, g.il2.sym_assembly_get_image, {as}, img) && img)
                g.images.assemblyCSharp = img;
        }
        static const char *kUnity[] = {"UnityEngine.CoreModule.dll", "UnityEngine.CoreModule",
                                       "UnityEngine.dll"};
        for (const char *name : kUnity) {
            if (g.images.unityCore) break;
            const uintptr_t np = scratch_cstr(s, g.pid, 4, name);
            uintptr_t as = 0, img = 0;
            if (np && remote_session_call(s, g.il2.sym_domain_assembly_open, {g.domain, np}, as) &&
                as && remote_session_call(s, g.il2.sym_assembly_get_image, {as}, img) && img)
                g.images.unityCore = img;
        }
    }
    const uintptr_t sizeSlot = remote_session_scratch(s, 0, sizeof(size_t));
    size_t count = 0;
    uintptr_t assemblies = 0;
    size_t zero = 0;
    if (!sizeSlot || !g.il2.sym_domain_get_assemblies) return;
    mem_write(g.pid, sizeSlot, &zero, sizeof(zero));
    if (!remote_session_call(s, g.il2.sym_domain_get_assemblies, {g.domain, sizeSlot}, assemblies) ||
        !mem_read(g.pid, sizeSlot, count) || !mem_ptr_ok(assemblies))
        return;
    if (count > 512) count = 512;
    for (size_t i = 0; i < count && g.images.all.size() < 512; ++i) {
        uintptr_t asmPtr = 0, image = 0;
        if (!mem_read(g.pid, assemblies + i * sizeof(uintptr_t), asmPtr) || !asmPtr) continue;
        if (!remote_session_call(s, g.il2.sym_assembly_get_image, {asmPtr}, image) || !image)
            continue;
        bool dup = false;
        for (uintptr_t x : g.images.all)
            if (x == image) dup = true;
        if (!dup) g.images.all.push_back(image);
    }
    auto push_unique = [](uintptr_t image) {
        if (!image) return;
        for (uintptr_t x : g.images.all)
            if (x == image) return;
        g.images.all.push_back(image);
    };
    push_unique(g.images.assemblyCSharp);
    push_unique(g.images.unityCore);
}

std::string trim(std::string s) {
    while (!s.empty() && std::isspace((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && std::isspace((unsigned char)s.back())) s.pop_back();
    return s;
}

} // namespace

int ax_list_processes(char *out, size_t cap) {
    if (!out || cap < 2) return 0;
    out[0] = '\0';
    DIR *d = opendir("/proc");
    if (!d) return put_text(out, cap, "cannot read /proc");
    struct Row {
        int pid;
        std::string name;
    };
    std::vector<Row> rows;
    const pid_t self = getpid();
    while (dirent *de = readdir(d)) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        const int pid = std::atoi(de->d_name);
        if (pid <= 1 || pid == self) continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *f = std::fopen(path, "rb");
        if (!f) continue;
        char cmd[240] = {};
        size_t n = std::fread(cmd, 1, sizeof(cmd) - 1, f);
        std::fclose(f);
        if (n == 0) continue;
        for (size_t i = 0; i < n; ++i)
            if (cmd[i] == '\0') cmd[i] = ' ';
        while (n > 0 && cmd[n - 1] == ' ') cmd[--n] = '\0';
        std::string name = cmd;
        if (name.empty()) continue;
        if (name.size() > 80) name.resize(80);
        rows.push_back({pid, name});
    }
    closedir(d);
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        const bool aa = a.name.find('.') != std::string::npos;
        const bool bb = b.name.find('.') != std::string::npos;
        if (aa != bb) return aa > bb;
        return a.name < b.name;
    });
    std::string text;
    const size_t limit = std::min(rows.size(), (size_t)180);
    for (size_t i = 0; i < limit; ++i) {
        char line[160];
        std::snprintf(line, sizeof(line), "%d %s\n", rows[i].pid, rows[i].name.c_str());
        text += line;
    }
    if (text.empty()) text = "no processes (root is required to see other apps)\n";
    return put_text(out, cap, text);
}

int ax_attach(int pid, char *out, size_t cap) {
    g = {};
    g.pid = (pid_t)pid;
    char procPath[64];
    std::snprintf(procPath, sizeof(procPath), "/proc/%d", pid);
    if (pid <= 0 || access(procPath, F_OK) != 0) return put_text(out, cap, "process is not running");
    if (!remote_detect_il2cpp(g.pid, g.il2)) {
        std::string msg = "IL2CPP not found in this process";
        if (g.il2.note[0]) {
            msg += "\n";
            msg += g.il2.note;
        }
        return put_text(out, cap, msg);
    }
    if (!g.il2.domain_ptr) remote_il2cpp_prime_domain(g.pid, g.il2);
    RemoteSession s{};
    std::string err;
    if (!remote_session_begin(g.pid, s))
        return put_text(out, cap, s.err[0] ? s.err : "ptrace attach failed");
    uintptr_t domain = 0;
    if (!g.il2.sym_domain_get ||
        !remote_session_call(s, g.il2.sym_domain_get, {}, domain) || !mem_ptr_ok(domain)) {
        remote_session_end(s);
        return put_text(out, cap, "il2cpp_domain_get failed");
    }
    g.domain = domain;
    g.il2.domain_ptr = domain;
    if (g.il2.sym_thread_attach) {
        uintptr_t thr = 0;
        remote_session_call(s, g.il2.sym_thread_attach, {domain}, thr);
    }
    collect_images(s);
    resolve_extra_syms();
    ensure_index(s);
    remote_session_end(s);
    g.ready = true;
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "pid %d\nlib %s\nbase 0x%llx\ndomain 0x%llx\nimages %zu\nclasses %zu\nready",
                  pid, g.il2.libBaseName, (unsigned long long)g.il2.base,
                  (unsigned long long)domain, g.images.all.size(), g.index.size());
    return put_text(out, cap, buf);
}

int ax_search(const char *query, char *out, size_t cap) {
    if (!g.ready || g.pid <= 0) return put_text(out, cap, "select a process first");
    const std::string q = trim(query ? query : "");
    if (q.empty()) return put_text(out, cap, "type a class name or 0x address");
    RemoteSession s{};
    std::string err;
    if (!open_session(s, err)) return put_text(out, cap, err);
    std::string text;
    if (looks_like_offset(q)) {
        const uintptr_t raw = (uintptr_t)std::strtoull(q.c_str(), nullptr, 0);
        text = search_by_address(s, raw);
    } else {
        const Found found = find_classes(s, q.c_str());
        if (found.hits.empty()) {
            char line[192];
            std::snprintf(line, sizeof(line),
                          "not found: %s\nindex %zu classes in %zu images",
                          q.c_str(), found.scanned, found.images);
            text = line;
        } else {
            char head[160];
            std::snprintf(head, sizeof(head), "matches %zu\nindex %zu classes in %zu images\n",
                          found.hits.size(), found.scanned, found.images);
            text = head;
            int detailed = 0;
            for (const Hit &hit : found.hits) {
                if (hit.rank >= 2 && detailed < 4) {
                    if (!hit.image.empty()) text += "[" + hit.image + "]\n";
                    text += describe(s, hit.klass, hit.typeName);
                    text += "\n";
                    ++detailed;
                } else {
                    char line[256];
                    std::snprintf(line, sizeof(line), "%s%s%s  0x%llx\n",
                                  hit.typeName.c_str(), hit.image.empty() ? "" : "  [",
                                  hit.image.empty() ? "" : (hit.image + "]").c_str(),
                                  (unsigned long long)hit.klass);
                    text += line;
                }
            }
        }
    }
    remote_session_end(s);
    return put_text(out, cap, text);
}
