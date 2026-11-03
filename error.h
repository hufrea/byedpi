#ifndef CIADPI_ERROR_H
#define CIADPI_ERROR_H

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#ifdef _WIN32
    #include <winsock2.h>
#endif
#ifdef ANDROID_APP
    #include <android/log.h>
#endif

#include "params.h"

#ifdef _WIN32
#define get_e() \
    unie(WSAGetLastError())
#else
#define get_e() \
    errno
#endif

#ifdef _WIN32
    #define uniperror(str) \
        fprintf(stderr, "%s: %ld\n", str, GetLastError())
#else
    #ifdef ANDROID_APP
    #define uniperror(str) \
        __android_log_print(ANDROID_LOG_ERROR, "proxy", \
            "%s: %s\n", str, strerror(errno))
    #else
    #define uniperror(str) \
        perror(str)
    #endif
#endif

static int unie(int e)
{
    #ifdef _WIN32
    switch (e) {
        case WSAEWOULDBLOCK:
            return EAGAIN;
        case WSAETIMEDOUT:
            return ETIMEDOUT;
        case WSAENETUNREACH:
            return ENETUNREACH;
        case WSAEHOSTUNREACH:
            return EHOSTUNREACH;
        case WSAECONNREFUSED:
            return ECONNREFUSED;
        case WSAECONNRESET:
            return ECONNRESET;
    }
    #endif
    return e;
}

#ifdef ANDROID_APP
    #define LOG_E ANDROID_LOG_ERROR
    #define LOG_S ANDROID_LOG_DEBUG
    #define LOG_L ANDROID_LOG_VERBOSE
    #define LOG(s, str, ...) \
        __android_log_print(s, "proxy", str, ##__VA_ARGS__)
    #define LOG_ENABLED 1
#else
    #define LOG_E -1
    #define LOG_S 1
    #define LOG_L 2
    static void LOG(int s, const char *str, ...) {
        if (params.debug >= s) {
            va_list args;
            va_start(args, str);
            vfprintf(stderr, str, args);
            va_end(args);
        }
    }
    #define LOG_ENABLED (params.debug >= LOG_S)
#endif

static struct addr_str {
    char s[INET6_ADDRSTRLEN];
}
straddr(union sockaddr_u dst)
{
    struct addr_str s;
    const char *p = 0;
    if (dst.sa.sa_family == AF_INET)
        p = inet_ntop(AF_INET, &dst.in.sin_addr, s.s, sizeof(s.s));
    else
        p = inet_ntop(AF_INET6, &dst.in6.sin6_addr, s.s, sizeof(s.s));
    if (!p) uniperror("inet_ntop");
    return s;
}

static struct err_str {
    char s[128];
}
strerr(int e)
{
    struct err_str s = {{ 'e','m','p','t','y' }};
    #ifdef _WIN32
    if (strerror_s(s.s, sizeof(s.s), e))
        uniperror("strerror_s");
    #else
    if (strerror_r(e, s.s, sizeof(s.s)))
        uniperror("strerror_r");
    #endif
    return s;
}

#endif

#define INIT_HEX_STR(b, s) \
    char HEX_STR[s * 2 + 1]; \
    HEX_STR[sizeof(HEX_STR) - 1] = 0; \
    do { \
        ssize_t i; \
        for (i = 0; i + 4 <= s; i += 4) \
            snprintf(HEX_STR + i * 2, sizeof(HEX_STR) - i * 2, \
                "%02x%02x%02x%02x", b[i],b[i+1],b[i+2],b[i+3]); \
        for (; i < s; i++) \
            snprintf(HEX_STR + i * 2, sizeof(HEX_STR) - i * 2, "%02x", b[i]); \
    } while (0);
