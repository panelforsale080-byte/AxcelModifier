#pragma once
#include <cstddef>

/** "pid\tname\n" lines. Returns bytes written, not including the NUL. */
int ax_list_processes(char *out, size_t cap);

/** Attach, il2cpp_domain_get, collect images. Status text in out. */
int ax_attach(int pid, char *out, size_t cap);

/** Class name, or a hex klass address / lib offset. Result text in out. */
int ax_search(const char *query, char *out, size_t cap);
