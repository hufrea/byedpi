int desync(int sfd, char *buffer, ssize_t n, struct sockaddr *dst);
int desync_udp(int fd, char *buffer, ssize_t n, struct sockaddr_in6 *dst);