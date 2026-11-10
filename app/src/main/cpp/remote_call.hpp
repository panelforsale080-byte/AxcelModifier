#pragma once
#include <cstdint>
#include <functional>
#include <sys/types.h>
#include <vector>

struct RemoteSession {
    pid_t pid = 0;
    pid_t tid = 0;
    bool attached = false;
#if defined(__aarch64__)
    alignas(8) unsigned char savedRegs[4096] = {};
    uint64_t sp = 0;
#endif
    char err[160] = {};
};

bool remote_session_begin(pid_t pid, RemoteSession &s);
bool remote_session_begin_try(pid_t pid, RemoteSession &s);
void remote_session_end(RemoteSession &s);

/* Scratch slots below tracee SP (16-byte aligned). Requires active session. */
uintptr_t remote_session_scratch(RemoteSession &s, int slot, size_t bytes);

bool remote_session_call(RemoteSession &s, uintptr_t func, const std::vector<uintptr_t> &args,
                         uintptr_t &ret_x0);

/* Single-shot (attach → one call → detach). */
bool remote_call(pid_t pid, uintptr_t func, const std::vector<uintptr_t> &args, uintptr_t &ret_x0,
                 char *err, size_t errCap);
