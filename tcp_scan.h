#ifndef TCP_SCAN_H
#define TCP_SCAN_H

typedef struct web_dir_st {
	char dir[256];
	struct list_head list;
}WEB_DIR;

typedef struct web_content_st {
	char content[256];
	struct list_head list;
}WEB_CONTENT;
	
int tcp_scan_port(unsigned int ip, unsigned int port, int proxy_flag, 
		void *proxy);

#endif
