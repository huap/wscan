/*
 * tcp_scan.c 
 * 
 * 2009/12/10   by wzt (c) Alibaba Security Group.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "wscan.h"
#include "list.h"
#include "tcp_scan.h"
#include "socks5.h"
#include "thread_pool.h"
#include "socket.h"
#include "debug.h"

char *data_m = "Accept: */*\r\n"
     		"Accept-Language: zh-cn\r\n"
       		"UA-CPU: x86\r\n"
        	"Accept-Encoding: gzip, deflate\r\n"
             	"User-Agent: Mozilla/4.0 (compatible; "
		"MSIE 6.0; Windows NT 5.2;"
             	"SV1; TencentTraveler ; .NET CLR 1.1.4322)\r\n";

char *data_e = "Connection: Keep-Alive\r\n\r\n";

struct list_head web_dir_list_head, web_content_list_head;

int tcp_scan_connect(unsigned int ip, unsigned int port, int proxy_flag, 
		void *proxy)
{
        PROXY *tmp_proxy = NULL;
        struct sockaddr_in serv_addr;
	struct timeval timeout;
        int sock_fd;

        serv_addr.sin_addr.s_addr = ip;
        if (proxy_flag == 0) {
                sock_fd = tcp_connect_nblock(ip, port, 5);
                if (sock_fd <= 0) {
                        /*
                        fprintf(stderr, "[-] Connect to %s:%d failed.\n", 
                                inet_ntoa(serv_addr.sin_addr), ntohs(port));
                        */
                        return 0;
                }
                fprintf(stderr, "\33[1;32m[+] Connect to %s:%d ok.\n\33[0m", 
                        inet_ntoa(serv_addr.sin_addr), ntohs(port));
        	timeout.tv_sec = READ_TIME_OUT;
        	timeout.tv_usec = 0;

        	if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, 
			(void *)&timeout, sizeof(timeout)) == -1) {
                	perror("setsockopt");
        	}
        	if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, 
			(void *)&timeout, sizeof(timeout)) == -1) {
                	perror("setsockopt");
        	}

        	set_sock_keep_alive(sock_fd, 1, TCP_KEEP_IDLE, 
			TCP_KEEP_INTERVAL, TCP_KEEP_COUNT );

                close(sock_fd);
        }
        if (proxy_flag == 1) {


        }
        if (proxy_flag == 2) {
                tmp_proxy = (PROXY *)proxy;
                sock_fd = socks5_client(inet_addr(tmp_proxy->ip), 
                        htons(tmp_proxy->port), ip, port);
                if (!sock_fd) {
                        //fprintf(stderr, "\33[1;31m[-] Socks5 session failed.\n\33[0m");
                        return 0;
                }
                fprintf(stderr, "\33[1;32m[+] Connect to %s:%d ok.\t-->\t"
                                "Socks5: %s:%d\33[0m\n", 
                        inet_ntoa(serv_addr.sin_addr), ntohs(port),
                        tmp_proxy->ip, tmp_proxy->port);
                close(sock_fd);
        }

        return sock_fd;
}
int tcp_scan_port(unsigned int ip, unsigned int port, int proxy_flag, 
		void *proxy)
{
	int sock_fd;

	sock_fd = tcp_scan_connect(ip, port, proxy_flag, proxy);
	
        return sock_fd;
}

void print_web_dir_list(void)
{
	WEB_DIR *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, (&web_dir_list_head)) {
		s = list_entry(p, WEB_DIR, list);
		if (s) {
			fprintf(stderr, "%s\n", s->dir);
		}
	}
}

void print_web_content_list(void)
{
	WEB_CONTENT *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, (&web_content_list_head)) {
		s = list_entry(p, WEB_CONTENT, list);
		if (s) {
			fprintf(stderr, "%s\n", s->content);
		}
	}
}

int init_web_list(char *file)
{
	WEB_DIR *web_dir = NULL;
	WEB_CONTENT *web_content = NULL;
	FILE *fp;
	char buff[1024];

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "[-] Open %s failed.\n", file);
		return 0;
	}
	
	INIT_LIST_HEAD(&web_dir_list_head);
	INIT_LIST_HEAD(&web_content_list_head);

	while (fgets(buff, 1024, fp) != NULL) {
		if (!strcmp(buff, "WEBDIR:")) {
			fprintf(stderr, "[+] Create web dir list.\n");
			goto web_dir;
		}
	}

	web_dir:
	while (fgets(buff, 1024, fp) != NULL) {
		if (!strcmp(buff, "WEBCONTENT:")) {
			fprintf(stderr, "[+] Create web content list.\n");
			goto web_content;
		}
		web_dir = (WEB_DIR *)malloc(sizeof(WEB_DIR));
		if (!web_dir) {
			fprintf(stderr, "[-] Malloc failed.\n");
			return 0;
		}

		strcpy(web_dir->dir, buff);
		wlist_add_tail(&(web_dir->list), &web_dir_list_head);
	}

	web_content:
	while (fgets(buff, 1024, fp) != NULL) {
		web_content = (WEB_CONTENT *)malloc(sizeof(WEB_CONTENT));
		if (!web_content) {
			fprintf(stderr, "[-] Malloc failed.\n");
			return 0;
		}

		strcpy(web_content->content, buff);
		wlist_add_tail(&(web_content->list), &web_content_list_head);
	}

	fclose(fp);
	return 1;
}

int http_scan(int sock_fd)
{

	return 1;
}

int web_content_scan(unsigned int ip, unsigned int port, int proxy_flag, 
		void *proxy)
{
	struct timeval timeout;
	int sock_fd;

	sock_fd = tcp_scan_connect(ip, port, proxy_flag, proxy);
	if (sock_fd <= 0) {
		return 0;
	}

	if (!proxy_flag) {
        	timeout.tv_sec = READ_TIME_OUT;
        	timeout.tv_usec = 0;

        	if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (
			void *)&timeout, sizeof(timeout)) == -1) {
                	perror("setsockopt.");
        	}
        	if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, 
			(void *)&timeout, sizeof(timeout)) == -1) {
                	perror("setsockopt.");
        	}

        	set_sock_keep_alive(sock_fd, 1, TCP_KEEP_IDLE, 
			TCP_KEEP_INTERVAL, TCP_KEEP_COUNT);
	}

	http_scan(sock_fd);

        return 1;
}
