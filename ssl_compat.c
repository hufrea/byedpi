#include "ssl_compat.h"

#include <stdio.h>
#include <openssl/ssl.h>
#include <dlfcn.h>

const SSL_METHOD *(*TLS_method_fn)(void) = NULL;
SSL_CTX *(*SSL_CTX_new_fn)(const SSL_METHOD*) = NULL;
int (*SSL_CTX_set_default_verify_paths_fn)(SSL_CTX*) = NULL;
int (*SSL_CTX_load_verify_locations_fn)(SSL_CTX*, const char *CAfile, const char *CApath) = NULL;
void (*SSL_CTX_set_verify_fn)(SSL_CTX*, int, SSL_verify_cb) = NULL;
SSL *(*SSL_new_fn)(SSL_CTX*) = NULL;
void *(*SSL_free_fn)(SSL*) = NULL;
int (*SSL_ctrl_fn)(SSL*, int, long, void*) = NULL;
int (*SSL_set_fd_fn)(SSL*, int) = NULL;
int (*SSL_connect_fn)(SSL*) = NULL;
int (*SSL_read_fn)(SSL*, void*, int) = NULL;
int (*SSL_write_fn)(SSL*, const void*, int) = NULL;

int ssl_load(void) {
    void *libssl = dlopen("libssl.so", RTLD_LAZY);
    if (!libssl) {
        fprintf(stderr, "%s\n", dlerror());
        return -1;
    }
    
    TLS_method_fn = dlsym(libssl, "TLS_method");
    SSL_CTX_new_fn = dlsym(libssl, "SSL_CTX_new");
    SSL_CTX_set_default_verify_paths_fn = dlsym(libssl, "SSL_CTX_set_default_verify_paths");
    SSL_CTX_load_verify_locations_fn = dlsym(libssl, "SSL_CTX_load_verify_locations");
    SSL_CTX_set_verify_fn = dlsym(libssl, "SSL_CTX_set_verify");
    SSL_new_fn = dlsym(libssl, "SSL_new");
    SSL_free_fn = dlsym(libssl, "SSL_free");
    SSL_ctrl_fn = dlsym(libssl, "SSL_ctrl");
    SSL_set_fd_fn = dlsym(libssl, "SSL_set_fd");
    SSL_connect_fn = dlsym(libssl, "SSL_connect");
    SSL_read_fn = dlsym(libssl, "SSL_read");
    SSL_write_fn = dlsym(libssl, "SSL_write");
    
    return 0;
}
