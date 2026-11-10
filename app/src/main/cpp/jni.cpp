#include "finder.hpp"
#include <jni.h>
#include <string>

static jstring text(JNIEnv *env, int (*fn)(char *, size_t), size_t cap) {
    std::string buf(cap, '\0');
    fn(buf.data(), buf.size());
    return env->NewStringUTF(buf.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_axcel_modifier_Native_listProcesses(JNIEnv *env, jclass) {
    return text(env, ax_list_processes, 48 * 1024);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_axcel_modifier_Native_attach(JNIEnv *env, jclass, jint pid) {
    std::string buf(2048, '\0');
    ax_attach((int)pid, buf.data(), buf.size());
    return env->NewStringUTF(buf.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_axcel_modifier_Native_search(JNIEnv *env, jclass, jstring query) {
    const char *q = query ? env->GetStringUTFChars(query, nullptr) : "";
    std::string buf(48 * 1024, '\0');
    ax_search(q ? q : "", buf.data(), buf.size());
    if (query) env->ReleaseStringUTFChars(query, q);
    return env->NewStringUTF(buf.c_str());
}
