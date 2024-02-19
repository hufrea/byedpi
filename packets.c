#define _GNU_SOURCE

#include <packets.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#define ANTOHS(data, i) \
    (uint16_t)((data[i] << 8) + (uint8_t)data[i + 1])
    

char tls_data[517] = {
    "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x03\x5f"
    "\x6f\x2c\xed\x13\x22\xf8\xdc\xb2\xf2\x60\x48\x2d\x72"
    "\x66\x6f\x57\xdd\x13\x9d\x1b\x37\xdc\xfa\x36\x2e\xba"
    "\xf9\x92\x99\x3a\x20\xf9\xdf\x0c\x2e\x8a\x55\x89\x82"
    "\x31\x63\x1a\xef\xa8\xbe\x08\x58\xa7\xa3\x5a\x18\xd3"
    "\x96\x5f\x04\x5c\xb4\x62\xaf\x89\xd7\x0f\x8b\x00\x3e"
    "\x13\x02\x13\x03\x13\x01\xc0\x2c\xc0\x30\x00\x9f\xcc"
    "\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24"
    "\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0"
    "\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c"
    "\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x01"
    "\x75\x00\x00\x00\x16\x00\x14\x00\x00\x11\x77\x77\x77"
    "\x2e\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x2e\x6f\x72"
    "\x67\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x16"
    "\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01"
    "\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x10\x00\x0e"
    "\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e"
    "\x31\x00\x16\x00\x00\x00\x17\x00\x00\x00\x31\x00\x00"
    "\x00\x0d\x00\x2a\x00\x28\x04\x03\x05\x03\x06\x03\x08"
    "\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05"
    "\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03"
    "\x02\x04\x02\x05\x02\x06\x02\x00\x2b\x00\x09\x08\x03"
    "\x04\x03\x03\x03\x02\x03\x01\x00\x2d\x00\x02\x01\x01"
    "\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x11\x8c\xb8"
    "\x8c\xe8\x8a\x08\x90\x1e\xee\x19\xd9\xdd\xe8\xd4\x06"
    "\xb1\xd1\xe2\xab\xe0\x16\x63\xd6\xdc\xda\x84\xa4\xb8"
    "\x4b\xfb\x0e\x00\x15\x00\xac\x00\x00\x00\x00\x00\x00"
};

char http_data[43] = {
    "GET / HTTP/1.1\r\n"
    "Host: www.wikipedia.org\r\n\r\n"
};


int find_tls_ext_offset(uint16_t type, char *data, size_t size) 
{
    if (size < 44) {
        return 0;
    }
    uint8_t sid_len = data[43];
    if (size < 44 + sid_len + 2) {
        return 0;
    }
    uint16_t cip_len = ANTOHS(data, 44 + sid_len);

    size_t skip = 44 + sid_len + 2 + cip_len + 4;
    if (size <= skip) {
        return 0;
    }
    uint16_t ext_len = ANTOHS(data, skip - 2);
    
    if (ext_len < (size - skip)) {
        size = ext_len + skip;
    }
    while ((skip + 4) < size) {
        uint16_t epyt = ANTOHS(data, skip);
        if (type == epyt) {
            return skip;
        }
        uint16_t len = ANTOHS(data, skip + 2);
        skip += (len + 4);
    }
    return 0;
}


int change_tls_sni(char *host, char *buffer, size_t bsize)
{
    int sni_offs, pad_offs;
    
    if (!(sni_offs = find_tls_ext_offset(0x00, buffer, bsize))) {
        return -1;
    }
    if (!(pad_offs = find_tls_ext_offset(0x15, buffer, bsize))) {
        return -1;
    }
    char *sni = &buffer[sni_offs];
    char *pad = &buffer[pad_offs];
    
    uint16_t old_sz = ANTOHS(buffer, sni_offs + 2) - 5;
    uint16_t free_sz = ANTOHS(buffer, pad_offs + 2);
    uint16_t new_sz = strlen(host);
    
    ssize_t diff = new_sz - old_sz;
  
    if ((free_sz != (bsize - pad_offs - 4)) 
            || free_sz < diff) {
        return -1;
    }
    *(uint16_t *)(sni + 2) = htons(old_sz + diff + 5);
    *(uint16_t *)(sni + 4) = htons(old_sz + diff + 3);
    *(uint16_t *)(sni + 7) = htons(old_sz + diff);
    *(uint16_t *)(pad + 2) = htons(free_sz - diff);
    
    char *host_end = sni + 9 + old_sz;
    int oth_sz = bsize - (sni_offs + 9 + old_sz);
    
    memmove(host_end + diff, host_end, oth_sz);
    memcpy(sni + 9, host, new_sz);
    return 0;
}


int parse_tls(char *buffer, size_t bsize, char **hs)
{
    if (ANTOHS(buffer, 0) != 0x1603) {
        return 0;
    }
    int sni_offs = find_tls_ext_offset(0x00, buffer, bsize);
    
    if (!sni_offs || (sni_offs + 12) >= bsize) {
        return 0;
    }
    uint16_t len = ANTOHS(buffer, sni_offs + 7);
    
    if ((sni_offs + 9 + len) > bsize) {
        return 0;
    }
    *hs = &buffer[sni_offs + 9];
    return len;
}


int parse_http(char *buffer, size_t bsize, char **hs, uint16_t *port)
{
    char *host = buffer, *h_end;
    size_t osz = bsize;
    
    if (bsize < 16 || *buffer > 'T' || *buffer < 'C') {
        return 0;
    }
    while (1) {
        host = memchr(host, '\n', osz);
        if (!host)
            return 0;
        host++;
        osz = bsize - (host - buffer);
        if (osz < 6)
            return 0;
        if (!strncasecmp(host, "Host:", 5))
            break;
    }
    host += 5; osz -= 5;
    for (; osz && isblank(*host); host++, osz--) {}
    
    char *l_end = memchr(host, '\n', osz);
    if (!l_end) {
        return 0;
    }
    for (; isspace(*(l_end - 1)); l_end--) {}
    
    if (!(isdigit(*(l_end - 1))))
        h_end = 0;
    else {
        char *h = host;
        h_end = 0;
        do {
            h = memchr(h, ':', l_end - h);
            if (h) h_end = h;
        } while (h);
    }
    
    if (!h_end) {
        if (port) *port = 80;
        h_end = l_end;
    }
    else if (port) {
        char *end;
        long i = strtol(h_end + 1, &end, 10);
        if (i <= 0 || end != l_end || i > 0xffff)
            return 0;
        *port = i;
    }
    *hs = host;
    return h_end - host;
}


int mod_http(char *buffer, size_t bsize, int m)
{
    char *host = 0, *par;
    int hlen = parse_http(buffer, bsize, &host, 0);
    if (!hlen)
        return -1;
    for (par = host - 1; *par != ':'; par--) {}
    par -= 4;
    if (m & MH_HMIX) {
        par[0] = tolower(par[0]);
        par[1] = toupper(par[1]);
        par[3] = toupper(par[3]);
    }
    if (m & MH_DMIX) {
        for (int i = 0; i < hlen; i += 2) {
            host[i] = toupper(host[i]);
        }
    }
    if (m & MH_SPACE) {
        for (; !isspace(*(host + hlen)); hlen++) {}
        int sc = host - (par + 5);
        memmove(par + 5, host, hlen);
        memset(par + 5 + hlen, '\t', sc);
    }
    return 0;
}


ssize_t part_tls(char *buffer, size_t bsize, ssize_t n, int pos)
{
    if ((n < 3) || (bsize - n < 5) || 
            (pos < 0) || (pos + 5 > n)) {
        return n;
    }
    uint16_t r_sz = ANTOHS(buffer, 3);
    if (r_sz < pos) {
        return n;
    }
    memmove(buffer + 5 + pos + 5, buffer + 5 + pos, n - (5 + pos));
    memcpy(buffer + 5 + pos, buffer, 3);
    
    *(uint16_t *)(buffer + 3) = htons(pos);
    *(uint16_t *)(buffer + 5 + pos + 3) = htons(r_sz - pos);
    return n + 5;
}
