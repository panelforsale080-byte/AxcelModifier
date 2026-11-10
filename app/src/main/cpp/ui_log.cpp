#include "ui_log.hpp"
#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <mutex>

namespace {
std::mutex g_mu;
constexpr size_t kMaxLines = 40;
constexpr size_t kLineCap = 200;
static char g_lines[kMaxLines][kLineCap];
static size_t g_start = 0;
static size_t g_count = 0;

void push_line(const char *line) {
    std::lock_guard<std::mutex> lock(g_mu);
    size_t slot;
    if (g_count < kMaxLines) {
        slot = (g_start + g_count) % kMaxLines;
        g_count++;
    } else {
        slot = g_start;
        g_start = (g_start + 1) % kMaxLines;
    }
    std::snprintf(g_lines[slot], kLineCap, "%s", line ? line : "");
}
} // namespace

void ui_log_clear() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_start = g_count = 0;
}

void ui_log(const char *fmt, ...) {
    char buf[kLineCap];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    push_line(buf);
}

void ui_log_copy_all(char *dst, size_t cap) {
    if (!dst || !cap) return;
    dst[0] = '\0';
    std::lock_guard<std::mutex> lock(g_mu);
    size_t used = 0;
    for (size_t i = 0; i < g_count; ++i) {
        const char *ln = g_lines[(g_start + i) % kMaxLines];
        const size_t n = std::strlen(ln);
        if (used + n + 2 >= cap) break;
        if (i > 0) dst[used++] = '\n';
        std::memcpy(dst + used, ln, n);
        used += n;
    }
    dst[used] = '\0';
}
