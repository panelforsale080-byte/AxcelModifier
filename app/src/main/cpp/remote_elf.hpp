#pragma once
#include <cstdint>
#include <sys/types.h>

struct ElfRemote {
    uintptr_t load_bias = 0;
    uintptr_t base = 0;
};

bool elf_file_map_bias(const char *path, uintptr_t map_base, uintptr_t &load_bias_out);
bool elf_remote_bias(pid_t pid, uintptr_t map_base, ElfRemote &out);
bool elf_remote_sym(pid_t pid, uintptr_t map_base, const char *name, uintptr_t &addr_out);
bool elf_file_sym(const char *path, uintptr_t load_bias, const char *name, uintptr_t &addr_out);
bool elf_file_sym_contains(const char *path, uintptr_t load_bias, const char *needle,
                           uintptr_t &addr_out, char *matched, size_t matchedCap);
