#ifndef SOCKS5_H
#define SOCKS5_H

#include "list.h"

#define SOCKS5_VERSION		0x05
#define SOCKS5_CONNECT		0x01
#define SOCKS5_IPV4		0x01
#define SOCKS5_DOMAIN		0x03
#define SOCKS5_IPV6		0x04

#define SOCKS5_USER		"wzt"
#define SOCKS5_PASSWD		"123456"

#define READ_TIME_OUT           30
#define WRITE_TIME_OUT          READ_TIME_OUT
            
#define TCP_KEEP_IDLE           3600
#define TCP_KEEP_INTERVAL       5
#define TCP_KEEP_COUNT          3 

typedef struct method_select_request {
	char version;
	char num_methods;
	char methods[255];
}METHOD_SELECT_REQ;

typedef struct method_select_response {
	char version;
	char select_method;
}METHOD_SELECT_RES;

typedef struct auth_request {
	char version;
	char name_len;
	char name[255];
	char pwd_len;
	char pwd[255];
}AUTH_REQ;

typedef struct auth_response {
	char version;
	char result;
}AUTH_RES;

typedef struct socks5_request {
	char version;
	char cmd;
	char reserved;
	char address_type;
	char other[1];
}SOCKS5_REQ;

typedef struct socks5_response {
	char version;
	char reply;
	char reserved;
	char address_type;
	char other[1];
}SOCKS5_RES;

/*
typedef struct http_proxy_arg_st {
	int flag;
	char http_server[128];
	int port;
}HTTP_PROXY_ARG;

typedef struct socks5_proxy_arg_st {
	int flag;
	char socks5_server[128];
	int port;
}SOCKS5_PROXY_ARG;
*/

typedef struct proxy_st {
	int id;
	char ip[128];
	int port;
	int flag;
	struct list_head list;
}PROXY;

typedef struct socks5_proxy_st {
	int proxy_id;
	int flag;
	char proxy_ip[128];
	int port;
	int max_port_num;
	int curr_run_num;
	int max_run_num;
	pthread_mutex_t socks5_lock;
	struct list_head list;
}SOCKS5_PROXY;

typedef struct http_proxy_st {
	int proxy_id;
	int flag;
	char proxy_ip[128];
	int port;
	int max_port_num;
	int curr_run_num;
	int max_run_num;
	pthread_mutex_t http_lock;
	struct list_head list;
}HTTP_PROXY;

#endif
