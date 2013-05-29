#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include "wscan.h"
#include "list.h"
#include "thread_pool.h"
#include "socket.h"
#include "socks5.h"
#include "debug.h"

extern SCAN_ARG g_scan_arg;

void wscan_usage(char *pro)
{
        fprintf(stderr,  
		"Usage: %s <type> <options>\n\n"
		"<Type>:\n"
		"port\t\tScan ports.\n"
		"pass\t\tCrack passwd.\n"
		"web\t\tScan web contents.\n"
		"\n<Options>:\n"
		"-h\t\tHost or Ip. Eg: www.alibaba-inc.com, 127.0.0.1/127.0.1.216\n"
		"-p\t\tPorts. Eg: 21-80,443,1024,3306-8080\n"
		"-s[N]\t\t1:HTTP Proxy 2:Socks5 Proxy.\n"
		"-n\t\tThread nums.\n"
		"-f\t\tIp list, Socks5/Http list.\n"
		"-o\t\tOutput file.\n",
		pro);
}

int main(int argc, char **argv)
{
        if (argc == 1) {
                wscan_usage(argv[0]);
                return 0;
        }

        if (!init_socks5_list()) {
                fprintf(stderr, "[-] Init socks5 list failed.\n");
                return 0;
        }
        fprintf(stderr, "[+] Init socks5 list ok\n");

        //print_socks5_list();
        strncpy(g_scan_arg.start_ip, argv[1], strlen(argv[1]) + 1);
        strncpy(g_scan_arg.end_ip, argv[2], strlen(argv[2]) + 1);
        g_scan_arg.start_port = atoi(argv[3]);
        g_scan_arg.end_port = atoi(argv[4]);

        if (!init_thread_pool(MAX_THREAD_NUM)) {
                return 0;
        }

        if (!start_add_worker_thread()) {
                return 0;
        }

        //print_worker_list();
        wait_all_thread_finsh();

        return 0;
}
