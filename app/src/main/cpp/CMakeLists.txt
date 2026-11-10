cmake_minimum_required(VERSION 3.22.1)
project(AxcelModifier)

add_library(axcel SHARED
    jni.cpp
    finder.cpp
    mem.cpp
    remote_call.cpp
    remote_elf.cpp
    remote_il2cpp.cpp
    ui_log.cpp)

target_compile_options(axcel PRIVATE -O2 -Wall -Wno-unused-function)

find_library(log-lib log)
target_link_libraries(axcel ${log-lib})
