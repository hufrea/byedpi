#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>

#define IS_TCP 1
#define IS_UDP 2
#define IS_HTTP 4
#define IS_HTTPS 8
//#define IS_QUIC 16
//#define IS_DNS 32

#define MH_HMIX 1
#define MH_SPACE 2
#define MH_DMIX 4

extern char tls_data[517];
extern char http_data[43];
extern char udp_data[64];

int change_tls_sni(const char *host, char *buffer, size_t bsize);

bool is_tls_chello(char *buffer, size_t bsize);

int parse_tls(char *buffer, size_t bsize, char **hs);

bool is_http(char *buffer, size_t bsize);

int parse_http(char *buffer, size_t bsize, char **hs, uint16_t *port);

int mod_http(char *buffer, size_t bsize, int m);

int get_http_code(char *b, size_t n);

bool is_http_redirect(char *req, size_t qn, char *resp, size_t sn);

bool neq_tls_sid(char *req, size_t qn, char *resp, size_t sn);

bool is_tls_shello(char *buffer, size_t bsize);

int part_tls(char *buffer, size_t bsize, ssize_t n, long pos);

//bool is_dns_req(char *buffer, size_t n);

//bool is_quic_initial(char *buffer, size_t bsize);


#endif
