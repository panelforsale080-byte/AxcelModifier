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
    bool ready = false;
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
    if (!buf || n == 0) return false;
    buf[0] = '\0';
    if (!mem_ptr_ok(p) || !mem_read(pid, p, buf, n - 1)) return false;
    buf[n - 1] = '\0';
    for (size_t i = 0; i < n; ++i) {
        if (buf[i] == '\0') return i > 0;
        const unsigned char c = (unsigned char)buf[i];
        if (c < 0x20 || c > 0x7e) {
            buf[0] = '\0';
            return false;
        }
    }
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

bool name_matches(pid_t pid, uintptr_t klass, const std::string &want) {
    char buf[96] = {};
    if (!klass_name_at(pid, klass, buf, sizeof(buf))) return false;
    if (want == buf) return true;
    const char *dot = std::strrchr(buf, '.');
    return dot && want == (dot + 1);
}

uintptr_t scan_images(RemoteSession &s, const std::string &wantCls) {
    if (!g.il2.sym_image_get_class || !g.il2.sym_image_get_class_count) return 0;
    for (uintptr_t image : g.images.all) {
        uintptr_t count = 0;
        if (!remote_session_call(s, g.il2.sym_image_get_class_count, {image}, count)) continue;
        const size_t n = (size_t)count;
        if (n == 0 || n > 12000) continue;
        const size_t limit = std::min(n, (size_t)6000);
        for (size_t i = 0; i < limit; ++i) {
            uintptr_t klass = 0;
            if (!remote_session_call(s, g.il2.sym_image_get_class, {image, i}, klass) || !klass)
                continue;
            if (name_matches(g.pid, klass, wantCls)) return klass;
        }
    }
    return 0;
}

uintptr_t find_class(RemoteSession &s, const char *fullName) {
    std::string ns, cls;
    split_name(fullName ? fullName : "", ns, cls);
    if (cls.empty()) return 0;
    uintptr_t klass = 0;
    if (g.images.assemblyCSharp)
        klass = class_from_name(s, g.images.assemblyCSharp, ns, cls);
    if (!klass && g.images.unityCore)
        klass = class_from_name(s, g.images.unityCore, ns, cls);
    if (!klass) {
        for (uintptr_t image : g.images.all) {
            klass = class_from_name(s, image, ns, cls);
            if (klass) break;
        }
    }
    if (!klass) klass = scan_images(s, cls);
    return klass;
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
}

bool call_cstr(RemoteSession &s, uintptr_t fn, uintptr_t arg, char *buf, size_t n) {
    if (!fn) return false;
    uintptr_t p = 0;
    if (!remote_session_call(s, fn, {arg}, p)) return false;
    return read_remote_cstr(g.pid, p, buf, n);
}

void append_fields(RemoteSession &s, uintptr_t klass, std::string &out) {
    if (!g.sym_class_get_fields || !g.il2.sym_field_get_offset) {
        out += "fields: il2cpp_class_get_fields not exported\n";
        return;
    }
    const uintptr_t iterSlot = remote_session_scratch(s, 8, sizeof(uintptr_t));
    if (!iterSlot) return;
    uintptr_t zero = 0;
    mem_write(g.pid, iterSlot, &zero, sizeof(zero));
    out += "fields:\n";
    int shown = 0;
    for (int i = 0; i < 400 && shown < 80; ++i) {
        uintptr_t field = 0;
        if (!remote_session_call(s, g.sym_class_get_fields, {klass, iterSlot}, field) ||
            !mem_ptr_ok(field))
            break;
        char name[80] = {};
        if (g.sym_field_get_name) call_cstr(s, g.sym_field_get_name, field, name, sizeof(name));
        uintptr_t off = 0;
        remote_session_call(s, g.il2.sym_field_get_offset, {field}, off);
        char line[120];
        std::snprintf(line, sizeof(line), "  %-28s 0x%llx\n", name[0] ? name : "?",
                      (unsigned long long)off);
        out += line;
        ++shown;
    }
    if (shown == 0) out += "  (none)\n";
}

std::string describe(RemoteSession &s, uintptr_t klass) {
    char name[96] = {};
    char ns[96] = {};
    if (!call_cstr(s, g.sym_class_get_name, klass, name, sizeof(name)))
        klass_name_at(g.pid, klass, name, sizeof(name));
    call_cstr(s, g.sym_class_get_namespace, klass, ns, sizeof(ns));
    if (!name[0]) return "address is not an Il2CppClass\n";
    char head[256];
    std::snprintf(head, sizeof(head),
                  "class %s%s%s\nklass 0x%llx\nlib %s base 0x%llx\n",
                  ns[0] ? ns : "", ns[0] ? "." : "", name, (unsigned long long)klass,
                  g.il2.libBaseName, (unsigned long long)g.il2.base);
    std::string out = head;
    append_fields(s, klass, out);
    return out;
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
    for (size_t i = 0; i < count && g.images.all.size() < 80; ++i) {
        uintptr_t asmPtr = 0, image = 0;
        if (!mem_read(g.pid, assemblies + i * sizeof(uintptr_t), asmPtr) || !asmPtr) continue;
        if (!remote_session_call(s, g.il2.sym_assembly_get_image, {asmPtr}, image) || !image)
            continue;
        bool dup = false;
        for (uintptr_t x : g.images.all)
            if (x == image) dup = true;
        if (!dup) g.images.all.push_back(image);
    }
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
    remote_session_end(s);
    resolve_extra_syms();
    g.ready = true;
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "pid %d\nlib %s\nbase 0x%llx\ndomain 0x%llx\nimages %zu\nready",
                  pid, g.il2.libBaseName, (unsigned long long)g.il2.base,
                  (unsigned long long)domain, g.images.all.size());
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
        uintptr_t klass = 0;
        if (mem_ptr_ok(raw)) klass = raw;
        else if (g.il2.base && g.il2.end > g.il2.base && raw < (g.il2.end - g.il2.base))
            klass = g.il2.base + raw;
        text = describe(s, klass);
        if (text.find("not an Il2CppClass") != std::string::npos) {
            char extra[160];
            std::snprintf(extra, sizeof(extra),
                          "\n%s is not a class pointer. Search the class name to list field offsets.",
                          q.c_str());
            text += extra;
        }
    } else {
        const uintptr_t klass = find_class(s, q.c_str());
        if (!klass)
            text = "not found: " + q + "\nfast class_from_name, then a short image scan";
        else
            text = describe(s, klass);
    }
    remote_session_end(s);
    return put_text(out, cap, text);
}
