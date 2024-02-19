#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
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
    fprintf(stderr, "%s: %d\n", str, WSAGetLastError())
#else
#define uniperror(str) \
    perror(str)
#endif

inline const int unie(int e)
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
    }
    #endif
    return e;
}
