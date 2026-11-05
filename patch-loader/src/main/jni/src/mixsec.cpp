// mixsec.cpp — LSPatch 的 native 层补充（针对字节系 RASP / 加固壳）
//
// 目标：把 Java 层拦不到的三类"原生证据"抹掉
//   1. /proc/self/maps 里出现的 lspatch 痕迹（RASP 会扫）
//   2. 对真实 APK 的 stat/open/pread（RASP 用它比对大小/哈希）
//   3. RASP 自己的检测线程（pthread_create 的入口落在已知安全库里 → 直接不给建）
//
// 用法：由 patch-loader 在 hookUniversal() 里 System.loadLibrary("mixsec")，
//       或者由 loader 显式调用 JNI 的 nativeInit(cacheApkPath, realApkPath)。
//
// 依赖：dobby（Vector 的 native 已经带 dobby_static）

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "dobby.h"

#define LOG_TAG "MixSec"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace {

std::string g_realApk;    // 真实安装路径 /data/app/.../base.apk
std::string g_cacheApk;   // 缓存原包路径 /data/user/0/<pkg>/cache/lspatch/origin/<crc>.apk
std::string g_mapsClean;  // 清洗过的 maps 副本

// RASP 线程入口所在的库（命中就不让建线程）
const char* kRaspLibs[] = {
        "libmetasec_ml.so",
        "libDexHelper.so",
        "libmsaoaidsec.so",
        "libshell-super.so",
        "libexec.so",
};

bool isRaspThread(void* start_routine) {
    if (start_routine == nullptr) return false;
    Dl_info info{};
    if (dladdr(start_routine, &info) == 0 || info.dli_fname == nullptr) return false;
    for (const char* lib : kRaspLibs) {
        if (strstr(info.dli_fname, lib) != nullptr) {
            LOGI("block rasp thread from %s", info.dli_fname);
            return true;
        }
    }
    return false;
}

// ---- pthread_create 过滤 -------------------------------------------------
int (*orig_pthread_create)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*) = nullptr;

int my_pthread_create(pthread_t* t, const pthread_attr_t* a, void* (*fn)(void*), void* arg) {
    if (isRaspThread(reinterpret_cast<void*>(fn))) {
        // 返回 0 但不起线程：RASP 会以为自己起来了
        return 0;
    }
    return orig_pthread_create(t, a, fn, arg);
}

// ---- open / openat / fopen 路径改写 --------------------------------------
bool isSelfApk(const char* p) {
    return p != nullptr && !g_realApk.empty() && strcmp(p, g_realApk.c_str()) == 0;
}

bool isMaps(const char* p) {
    return p != nullptr && strcmp(p, "/proc/self/maps") == 0;
}

int (*orig_open)(const char*, int, ...) = nullptr;
int (*orig_openat)(int, const char*, int, ...) = nullptr;
FILE* (*orig_fopen)(const char*, const char*) = nullptr;

int my_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    if (isMaps(path) && !g_mapsClean.empty()) return orig_open(g_mapsClean.c_str(), flags, mode);
    if (isSelfApk(path) && !g_cacheApk.empty()) return orig_open(g_cacheApk.c_str(), flags, mode);
    return orig_open(path, flags, mode);
}

int my_openat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    if (isMaps(path) && !g_mapsClean.empty()) return orig_openat(dirfd, g_mapsClean.c_str(), flags, mode);
    if (isSelfApk(path) && !g_cacheApk.empty()) return orig_openat(dirfd, g_cacheApk.c_str(), flags, mode);
    return orig_openat(dirfd, path, flags, mode);
}

FILE* my_fopen(const char* path, const char* mode) {
    if (isMaps(path) && !g_mapsClean.empty()) return orig_fopen(g_mapsClean.c_str(), mode);
    if (isSelfApk(path) && !g_cacheApk.empty()) return orig_fopen(g_cacheApk.c_str(), mode);
    return orig_fopen(path, mode);
}

// ---- stat 系列：让 RASP 看到缓存原包的大小/时间 ---------------------------
int (*orig_stat)(const char*, struct stat*) = nullptr;
int (*orig_lstat)(const char*, struct stat*) = nullptr;

int my_stat(const char* path, struct stat* st) {
    if (isSelfApk(path) && !g_cacheApk.empty()) return orig_stat(g_cacheApk.c_str(), st);
    return orig_stat(path, st);
}

int my_lstat(const char* path, struct stat* st) {
    if (isSelfApk(path) && !g_cacheApk.empty()) return orig_lstat(g_cacheApk.c_str(), st);
    return orig_lstat(path, st);
}

// ---- maps 清洗 -----------------------------------------------------------
// 读 /proc/self/maps，把含 lspatch / mixsec 的行删掉，写到 cache 下的副本
void buildCleanMaps(const std::string& out) {
    FILE* in = orig_fopen("/proc/self/maps", "r");
    if (in == nullptr) return;
    FILE* of = orig_fopen(out.c_str(), "w");
    if (of == nullptr) {
        fclose(in);
        return;
    }
    char line[4096];
    while (fgets(line, sizeof(line), in) != nullptr) {
        if (strstr(line, "lspatch") != nullptr) continue;
        if (strstr(line, "mixsec") != nullptr) continue;
        fputs(line, of);
    }
    fclose(in);
    fclose(of);
}

void* sym(const char* name) {
    void* p = dlsym(RTLD_DEFAULT, name);
    if (p == nullptr) p = dlsym(RTLD_NEXT, name);
    return p;
}

void installHooks() {
    void* p;

    p = sym("pthread_create");
    if (p != nullptr) DobbyHook(p, reinterpret_cast<void*>(my_pthread_create),
                                reinterpret_cast<void**>(&orig_pthread_create));

    p = sym("open");
    if (p != nullptr) DobbyHook(p, reinterpret_cast<void*>(my_open),
                                reinterpret_cast<void**>(&orig_open));

    p = sym("openat");
    if (p != nullptr) DobbyHook(p, reinterpret_cast<void*>(my_openat),
                                reinterpret_cast<void**>(&orig_openat));

    p = sym("fopen");
    if (p != nullptr) DobbyHook(p, reinterpret_cast<void*>(my_fopen),
                                reinterpret_cast<void**>(&orig_fopen));

    p = sym("stat");
    if (p != nullptr) DobbyHook(p, reinterpret_cast<void*>(my_stat),
                                reinterpret_cast<void**>(&orig_stat));

    p = sym("lstat");
    if (p != nullptr) DobbyHook(p, reinterpret_cast<void*>(my_lstat),
                                reinterpret_cast<void**>(&orig_lstat));

    LOGI("hooks installed");
}

}  // namespace

static std::string readCmdlinePkg() {
    FILE* f = fopen("/proc/self/cmdline", "r");
    if (f == nullptr) return {};
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return {};
    std::string s(buf, n);
    size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);
    return s;
}

static void derivePaths() {
    std::string pkg = readCmdlinePkg();
    if (!pkg.empty()) {
        g_mapsClean = "/data/user/0/" + pkg + "/cache/maps_clean.txt";
    }
    // 从 maps 里找真实 apk 和缓存原包
    FILE* f = fopen("/proc/self/maps", "r");
    if (f == nullptr) return;
    char line[4096];
    while (fgets(line, sizeof(line), f) != nullptr) {
        if (g_cacheApk.empty() && strstr(line, "/lspatch/origin/") != nullptr) {
            char* p = strchr(line, '/');
            if (p != nullptr) {
                std::string s(p);
                while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
                g_cacheApk = s;
            }
        }
        if (g_realApk.empty() && strstr(line, "/base.apk") != nullptr &&
            strstr(line, "/data/app/") != nullptr) {
            char* p = strchr(line, '/');
            if (p != nullptr) {
                std::string s(p);
                while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
                g_realApk = s;
            }
        }
    }
    fclose(f);
}

extern "C" JNIEXPORT void JNICALL
Java_org_lsposed_lspatch_metaloader_LSPAppComponentFactoryStub_nativeInitMixSec(JNIEnv*, jclass) {
    derivePaths();
    LOGI("init: real=%s cache=%s maps=%s", g_realApk.c_str(), g_cacheApk.c_str(), g_mapsClean.c_str());
    buildCleanMaps(g_mapsClean);
    installHooks();
}

extern "C" JNIEXPORT void JNICALL
Java_org_lsposed_lspatch_loader_SigBypass_nativeInit(JNIEnv* env, jclass,
                                                     jstring realApk, jstring cacheApk,
                                                     jstring mapsClean) {
    if (realApk != nullptr) {
        const char* s = env->GetStringUTFChars(realApk, nullptr);
        g_realApk = s;
        env->ReleaseStringUTFChars(realApk, s);
    }
    if (cacheApk != nullptr) {
        const char* s = env->GetStringUTFChars(cacheApk, nullptr);
        g_cacheApk = s;
        env->ReleaseStringUTFChars(cacheApk, s);
    }
    if (mapsClean != nullptr) {
        const char* s = env->GetStringUTFChars(mapsClean, nullptr);
        g_mapsClean = s;
        env->ReleaseStringUTFChars(mapsClean, s);
    }
    buildCleanMaps(g_mapsClean);
    installHooks();
}
