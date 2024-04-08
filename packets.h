#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
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

int get_http_code(char *b, size_t n);

bool is_http_redirect(char *req, size_t qn, char *resp, size_t sn);

bool neq_tls_sid(char *req, size_t qn, char *resp, size_t sn);

bool is_tls_alert(char *resp, size_t sn);

int part_tls(char *buffer, size_t bsize, ssize_t n, long pos);
