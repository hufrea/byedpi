#ifndef CIADPI_ERROR_H
#define CIADPI_ERROR_H

#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
    #include <winsock2.h>
#endif
#ifdef ANDROID_APP
    #include <android/log.h>
#endif

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

static inline const int unie(int e)
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
#else
    #define LOG_E -1
    #define LOG_S 1
    #define LOG_L 2
    #define LOG(s, str, ...) \
        if (params.debug >= s) \
            fprintf(stderr, str, ##__VA_ARGS__)
#endif

#define INIT_ADDR_STR(dst) \
    char ADDR_STR[INET6_ADDRSTRLEN]; \
    const char *p = 0; \
    if (dst.sa.sa_family == AF_INET) \
        p = inet_ntop(AF_INET, &dst.in.sin_addr, ADDR_STR, sizeof(ADDR_STR)); \
    else \
        p = inet_ntop(AF_INET6, &dst.in6.sin6_addr, ADDR_STR, sizeof(ADDR_STR)); \
    if (!p) uniperror("inet_ntop");

#endif
