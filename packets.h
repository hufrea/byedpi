#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#define IS_UNKNOWN 0
#define IS_HTTP 1
#define IS_HTTPS 2

#define MH_HMIX 1
#define MH_SPACE 2
#define MH_DMIX 4

extern char tls_data[517];
extern char http_data[43];

int change_tls_sni(const char *host, char *buffer, size_t bsize);

int parse_tls(char *buffer, size_t bsize, char **hs);

int parse_http(char *buffer, size_t bsize, char **hs, uint16_t *port);

int mod_http(char *buffer, size_t bsize, int m);

int part_tls(char *buffer, size_t bsize, ssize_t n, int pos);
