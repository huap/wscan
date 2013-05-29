#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "socks5.h"
#include "socket.h"
#include "debug.h"

int socks5_select_method(int sock_fd)
{
	METHOD_SELECT_REQ *method_req;
	METHOD_SELECT_RES *method_res;
	char buff[128] = {0};
	int ret;

	method_req = (METHOD_SELECT_REQ *)buff;
	method_req->version = SOCKS5_VERSION;
	method_req->num_methods = 0x02;
	method_req->methods[0] = 0x00;
	method_req->methods[1] = 0x02;

	ret = write(sock_fd, buff, 4);
	if (ret <= 0) {
		perror("write");
		return 0;
	}	
	//printf("%d:%s\n", ret, buff);

	memset(buff, '\0', 128);
	ret = read(sock_fd, buff, 128);
	if (ret <= 0) {
		perror("read");
		return 0;
	}
	//printf("%d:%s\n", ret, buff);

	method_res = (METHOD_SELECT_RES *)buff;
	if (method_res->version != SOCKS5_VERSION) {
		DbgPrint("%s", "[-] Not socks5 version.\n");
		return 0;
	}
	DbgPrint("%s", "[+] Version: 0x05.\n");

	//printf("%d\n", method_res->select_method);
	if (method_res->select_method == 0x0) {
		//fprintf(stderr, "[+] Socks5 method: 0x0.\n");
		return 1;
	} else if (method_res->select_method == 0x02) {
		//fprintf(stderr, "[+] Socks5 method: 0x02.\n");
		return 2;
	}
	else {
		//fprintf(stderr, "[-] Socks5 method select failed.\n");
        	return 0;
	}
}

int socks5_auth_user(int sock_fd)
{
	AUTH_RES *auth_res;
	char buff[512] = {0};
        int name_len, pwd_len;
        int pack_len;
	int ret;

        memset(buff, '\0', 512);

	name_len = strlen(SOCKS5_USER);
	pwd_len = strlen(SOCKS5_PASSWD);
        buff[0] = 0x05;
        buff[1] = name_len;
        strcpy(buff + 2, SOCKS5_USER);

        buff[2 + name_len] = pwd_len;
        strcpy(buff + 2 + name_len + 1, SOCKS5_PASSWD);

        pack_len = 3 + name_len + pwd_len;
	//printf("%d\n", pack_len);

	ret = write(sock_fd, buff, pack_len);
	if (ret <= 0) {
		perror("write");
		return 0;
	}
	//printf("write: %d\n", ret);

	memset(buff, '\0', 512);
	ret = read(sock_fd, buff, 512);
	if (ret <= 0) {
		perror("read");
		return 0;
	}
	//printf("read: %d\n", ret);

	auth_res = (AUTH_RES *)buff;
	if (auth_res->version != 0x1) {
		DbgPrint("%s", "[-] Socks5 wrong version.\n");
		return 0;
	}
	if (auth_res->result != 0x0) {
		DbgPrint("%s", "[-] Socks5 wrong user or passwd.\n");
		return 0;
	}

	DbgPrint("%s", "[+] Socks5 auth user successful.\n");
	return 1;
}

int socks5_send_ip(int sock_fd, unsigned int ip, unsigned int port)
{
	struct sockaddr_in serv_addr;
	SOCKS5_REQ *socks5_req;
	SOCKS5_RES *socks5_res;
	unsigned int tmp_ip = ip;
	unsigned int tmp_port = port;
	char buff[128];
	int pack_len;
	int ret;

	//printf("%x, %x\n", tmp_ip, tmp_port);

	memset(buff, '\0', 128);
	socks5_req = (SOCKS5_REQ *)buff;
	
	socks5_req->version = 0x5;
	socks5_req->cmd = 0x1;
	socks5_req->reserved = 0x0;
	socks5_req->address_type = 0x1;

	memcpy(socks5_req->other, &tmp_ip, 4);
	memcpy(socks5_req->other + 4, &tmp_port, 2);
	
	pack_len = sizeof(SOCKS5_REQ) + 5;
	ret = write(sock_fd, buff, pack_len);
	if (ret <= 0) {
		perror("write");
		return 0;
	}

	memset(buff, '\0', 128);
	ret = read(sock_fd, buff, 128);
	if (ret <= 0) {
		perror("read");
		return 0;
	}

	socks5_res = (SOCKS5_RES *)buff;
	if (socks5_res->version != SOCKS5_VERSION) {
		DbgPrint("%s", "[-] Not correct socks5 version.\n");
		return 0;
	}
	if (socks5_res->reply != 0x0) {
		DbgPrint("%s", "[-] Not correct socks5 reply.\n");
		return 0;
	}
	DbgPrint("%s", "[+] Send socks5 domain ok.\n");

        memcpy(&serv_addr.sin_addr.s_addr,
                &socks5_res->other, 4);
        memcpy(&serv_addr.sin_port,
                &socks5_res->other + 4, 2);
	DbgPrint("%s", "[+] Socks5 worker ip and port: %s:%d\n",
		inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));

	return 1;
}

int socks5_client(unsigned int socks5_ip, unsigned int socks5_port,
	unsigned int target_ip, unsigned int target_port)
{
	struct timeval timeout;
	int sock_fd;
	int ret;

	sock_fd = tcp_connect_nblock(socks5_ip, socks5_port, 5);
	if (sock_fd <= 0) {
		DbgPrint("%s", "[-] Connect to socks5 server failed.\n");
		return 0;
	}
	DbgPrint("%s", "[+] Connect to socks5 server ok.\n");

        timeout.tv_sec = READ_TIME_OUT;
        timeout.tv_usec = 0;

        if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (void *)&timeout,
                sizeof(timeout)) == -1) {
                perror("setsockopt.");
        }
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout,
                sizeof(timeout)) == -1) {
                perror("setsockopt.");
        }

        set_sock_keep_alive(sock_fd, 1, TCP_KEEP_IDLE, TCP_KEEP_INTERVAL,
                TCP_KEEP_COUNT );

	DbgPrint("%s", "[+] Start socks5 method select ...\n");	
	ret = socks5_select_method(sock_fd);
	if (ret == 0) {
		close(sock_fd);
		return 0;
	}
	if (ret == 2) {
		DbgPrint("%s", "[+] Start socks5 user auth ...\n");	
		if (!socks5_auth_user(sock_fd)) {
			close(sock_fd);
			return 0;
		}
	}

	if (!socks5_send_ip(sock_fd, target_ip, target_port)) {
		close(sock_fd);
		return 0;
	}

	return sock_fd;
}
