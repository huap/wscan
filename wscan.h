#ifndef WSCAN_H
#define WSCAN_H

typedef struct scan_arg_st {
	char start_ip[128];
	char end_ip[128];
	unsigned int start_port;
	unsigned int end_port;
}SCAN_ARG;

enum scan_type {PORT_SCAN, CRACK_PASSWD, WEB};

#endif
