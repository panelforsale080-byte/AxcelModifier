#pragma once
#include <cstddef>

void ui_log(const char *fmt, ...);
void ui_log_clear();
void ui_log_copy_all(char *dst, size_t cap);
