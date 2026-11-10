#include "remote_call.hpp"
#include "mem.hpp"
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)

#include <linux/elf.h>
#include <sys/user.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

static std::mutex g_ptraceSessionMu;

static pid_t pick_tracee_tid(pid_t pid) { return pid; }

static struct user_pt_regs *saved_pt(RemoteSession &s) {
    return reinterpret_cast<struct user_pt_regs *>(s.savedRegs);
}

static bool get_regs(pid_t tid, struct user_pt_regs &regs) {
    struct iovec iov{&regs, sizeof(regs)};
    return ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

static bool set_regs(pid_t tid, const struct user_pt_regs &regs) {
    struct iovec iov{const_cast<struct user_pt_regs *>(&regs), sizeof(regs)};
    return ptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

static bool stable_ptrace_attach(pid_t tid) {
    if (ptrace(PTRACE_SEIZE, tid, nullptr, (void *)PTRACE_O_TRACESYSGOOD) != 0) return false;
    if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0) return false;
    int st = 0;
    return waitpid(tid, &st, 0) == tid;
}

static bool session_begin_locked(pid_t pid, RemoteSession &s) {
    s = RemoteSession{};
    s.pid = pid;
    s.tid = pick_tracee_tid(pid);
    if (!stable_ptrace_attach(s.tid)) {
        std::snprintf(s.err, sizeof(s.err), "PTRACE_SEIZE: %s", std::strerror(errno));
        return false;
    }
    auto *saved = saved_pt(s);
    if (!get_regs(s.tid, *saved)) {
        std::snprintf(s.err, sizeof(s.err), "GETREGSET fail");
        ptrace(PTRACE_DETACH, s.tid, nullptr, nullptr);
        return false;
    }
    s.sp = saved->sp;
    s.attached = true;
    return true;
}

bool remote_session_begin(pid_t pid, RemoteSession &s) {
    g_ptraceSessionMu.lock();
    if (!session_begin_locked(pid, s)) {
        g_ptraceSessionMu.unlock();
        return false;
    }
    return true;
}

bool remote_session_begin_try(pid_t pid, RemoteSession &s) {
    if (!g_ptraceSessionMu.try_lock()) {
        std::snprintf(s.err, sizeof(s.err), "ptrace busy");
        return false;
    }
    if (!session_begin_locked(pid, s)) {
        g_ptraceSessionMu.unlock();
        return false;
    }
    return true;
}

void remote_session_end(RemoteSession &s) {
    if (s.attached) {
        set_regs(s.tid, *saved_pt(s));
        ptrace(PTRACE_DETACH, s.tid, nullptr, nullptr);
        s.attached = false;
    }
    g_ptraceSessionMu.unlock();
}

uintptr_t remote_session_scratch(RemoteSession &s, int slot, size_t bytes) {
    if (!s.attached || slot < 0 || slot > 32) return 0;
    const size_t need = (bytes + 15) & ~size_t(15);
    const uintptr_t base = (uintptr_t)(s.sp - 0x800ULL - (uintptr_t)slot * 0x80ULL);
    if (need > 0x70) return 0;
    std::vector<uint8_t> z(need, 0);
    if (!mem_write(s.pid, base, z.data(), need)) return 0;
    return base;
}

bool remote_session_call(RemoteSession &s, uintptr_t func, const std::vector<uintptr_t> &args,
                         uintptr_t &ret_x0) {
    ret_x0 = 0;
    if (!s.attached || !func) {
        std::snprintf(s.err, sizeof(s.err), "session/call invalid");
        return false;
    }
    struct user_pt_regs work = *saved_pt(s);
    for (size_t i = 0; i < args.size() && i < 8; ++i)
        work.regs[i] = args[i];
    work.pc = func;
    work.regs[30] = 0;
    if (!set_regs(s.tid, work)) {
        std::snprintf(s.err, sizeof(s.err), "SETREGSET fail");
        return false;
    }
    ptrace(PTRACE_CONT, s.tid, nullptr, nullptr);
    int st = 0;
    bool success = false;
    for (int i = 0; i < 40; ++i) {
        const pid_t w = waitpid(s.tid, &st, WNOHANG);
        if (w == s.tid) {
            success = true;
            break;
        }
        if (w < 0 && errno != EINTR) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!success) {
        ptrace(PTRACE_INTERRUPT, s.tid, nullptr, nullptr);
        (void)waitpid(s.tid, &st, 0);
        std::snprintf(s.err, sizeof(s.err), "ptrace call timeout");
    }
    if (!get_regs(s.tid, work)) {
        std::snprintf(s.err, sizeof(s.err), "GETREGSET after call");
        set_regs(s.tid, *saved_pt(s));
        return false;
    }
    ret_x0 = (uintptr_t)work.regs[0];
    if (!set_regs(s.tid, *saved_pt(s))) {
        std::snprintf(s.err, sizeof(s.err), "restore regs fail");
        return false;
    }
    return success;
}

bool remote_call(pid_t pid, uintptr_t func, const std::vector<uintptr_t> &args, uintptr_t &ret_x0,
                 char *err, size_t errCap) {
    RemoteSession s{};
    if (!remote_session_begin(pid, s)) {
        std::snprintf(err, errCap, "%s", s.err);
        return false;
    }
    const bool ok = remote_session_call(s, func, args, ret_x0);
    if (!ok) std::snprintf(err, errCap, "%s", s.err);
    remote_session_end(s);
    return ok;
}

#else

bool remote_session_begin(pid_t, RemoteSession &s) {
    std::snprintf(s.err, sizeof(s.err), "arm64 only");
    return false;
}
bool remote_session_begin_try(pid_t, RemoteSession &s) {
    std::snprintf(s.err, sizeof(s.err), "arm64 only");
    return false;
}
void remote_session_end(RemoteSession &) {}
uintptr_t remote_session_scratch(RemoteSession &, int, size_t) { return 0; }
bool remote_session_call(RemoteSession &, uintptr_t, const std::vector<uintptr_t> &, uintptr_t &) {
    return false;
}
bool remote_call(pid_t, uintptr_t, const std::vector<uintptr_t> &, uintptr_t &, char *err,
                 size_t errCap) {
    std::snprintf(err, errCap, "arm64 only");
    return false;
}

#endif
