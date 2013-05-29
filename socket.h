#ifndef LIBSOCK_H
#define LIBSOCK_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_LISTEN_USER         100

unsigned int make_network_ip(char *host);
int get_ip_of_domain(char *domain, char *ip_addr);
int get_ip_of_domain_safe(char *domain, char *ip_addr);
int tcp_connect(unsigned int remote_ip, unsigned int remote_port);
int tcp_connect_timeout(unsigned int remote_ip, unsigned int remote_port, 
	struct timeval timeout);
int tcp_connect_nblock(unsigned int remote_ip,
                unsigned int remote_port, int timeout);
int tcp_connect_fast(unsigned int remote_ip,
                unsigned int remote_port, int timeout);
ssize_t sock_readn(int sock_id, char *ptr, size_t n);
ssize_t sock_writen(int sock_id, char *ptr, size_t n);
ssize_t sock_read_timeout(int sock_id, char *buff, size_t n, int time_out);
ssize_t sock_write_timeout(int sock_id, char *buff, size_t n, int time_out);
ssize_t sock_readn_timeout(int sock_id, char *ptr, size_t n, int time_out);
ssize_t sock_writen_timeout(int sock_id, char *ptr, size_t n, int time_out);
int bind_sock(unsigned int port);
int listen_server(unsigned int port);

#endif	/* _LIBSOCK_H_ */
