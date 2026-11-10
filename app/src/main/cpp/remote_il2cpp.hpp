#pragma once
#include <cstddef>
#include <cstdint>
#include <sys/types.h>

struct RemoteIl2CppInfo {
    char libPath[512] = {};
    char libBaseName[128] = {};
    uintptr_t base = 0;
    uintptr_t end = 0;
    uintptr_t sym_domain_get = 0;
    uintptr_t sym_domain_assembly_open = 0;
    uintptr_t sym_class_from_name = 0;
    uintptr_t sym_domain_get_assemblies = 0;
    uintptr_t sym_assembly_get_image = 0;
    uintptr_t sym_image_get_class_count = 0;
    uintptr_t sym_image_get_class = 0;
    uintptr_t sym_class_get_field_from_name = 0;
    uintptr_t sym_field_static_get_value = 0;
    uintptr_t sym_thread_attach = 0;
    uintptr_t sym_class_get_method_from_name = 0;
    uintptr_t sym_field_get_offset = 0;
    uintptr_t sym_runtime_invoke = 0;
    uintptr_t domain_ptr = 0;
    bool export_domain_get = false;
    bool export_class_from_name = false;
    bool export_domain_get_assemblies = false;
    bool export_assembly_get_image = false;
    bool export_class_get_field_from_name = false;
    bool export_field_static_get_value = false;
    bool export_thread_attach = false;
    char note[256] = {};
};

bool remote_detect_il2cpp(pid_t pid, RemoteIl2CppInfo &out);
bool remote_refresh_domain_ptr(pid_t pid, RemoteIl2CppInfo &io);
/** One-shot il2cpp_domain_get in target (fills domain_ptr when static decode fails). */
bool remote_il2cpp_prime_domain(pid_t pid, RemoteIl2CppInfo &io);
void remote_il2cpp_invalidate_cache(pid_t pid);
