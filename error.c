#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

int unie(int e)
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

int get_e()
{
    #ifdef _WIN32
    int e = WSAGetLastError();
    return unie(e);
    #else
    return errno;
    #endif
}

void uniperror(char *str)
{
    #ifdef _WIN32
    int e = WSAGetLastError();
    fprintf(stderr, "%s: %d\n", str, e);
    #else
    perror(str);
    #endif
}
