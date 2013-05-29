/*
 * Scan_engine.c 
 * 	
 * Scan engine is a thread pool that schedule threads to call 
 * certain scan function.
 *
 * 2009/12/10	by wzt (c) Alibaba Security Group.
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
#include "socks5.h"
#include "thread_pool.h"
#include "tcp_scan.h"
#include "socket.h"
#include "debug.h"

THREAD_POOL *thread_pool = NULL;
SCAN_ARG g_scan_arg;

int add_all_worker_flag = 0;
int g_proxy_flag = 0;

struct list_head socks5_list_head, proxy_list_head;
pthread_mutex_t list_lock;

int (*scan_fn)(unsigned int, unsigned int, int, void *);

/**
 * Create thread list and start it.
 */
int init_thread_pool(int thread_num)
{
	int i;

	thread_pool = (THREAD_POOL *)malloc(sizeof(THREAD_POOL));
	if (!thread_pool) {
		fprintf(stderr, "Malloc failed.\n");
		return 0;
	}

	thread_pool->thread_id = 
		(pthread_t *)malloc(sizeof(pthread_t) * thread_num);
	if (!thread_pool->thread_id) {
		fprintf(stderr, "Malloc failed.\n");
		free(thread_pool);
		return 0;
	}	

	pthread_mutex_init(&(thread_pool->queue_lock), NULL);
	pthread_cond_init(&(thread_pool->queue_ready), NULL);
	INIT_LIST_HEAD(&(thread_pool->worker_list_head));
	thread_pool->destroy_flag = 0;
	thread_pool->max_thread_num = thread_num;
	thread_pool->curr_worker_num = 0;

	for (i = 0; i < thread_num; i++) {
		if (pthread_create(&(thread_pool->thread_id[i]), NULL,
			worker_thread, NULL) != 0) {
			perror("pthread_create");
			return 0;
		}
		fprintf(stderr, "[+] Create thread %d ok.\n", i);
	}

	return 1;
}

/**
 * Add a worker to wait queue.
 */
int add_worker(void *arg, int (*fn)(unsigned int, unsigned int, int, void *), 
		unsigned int ip, unsigned int port)
{
	THREAD_WORKER *new_worker = NULL;

	new_worker = (THREAD_WORKER *)malloc(sizeof(THREAD_WORKER));
	if (!new_worker) {
		fprintf(stderr, "Malloc failed.\n");
		return 0;
	}

	new_worker->tcp_scan_port = fn;
	new_worker->ip = ip;
	new_worker->port = port;

	/* check proxy flag, 0: no proxy, 1: http proxy, 2: socks5 proxy.*/
	switch (g_proxy_flag) {
		case 0:
			new_worker->proxy_flag = 0;
			new_worker->proxy = NULL;
			break;
		case 1:
			new_worker->proxy_flag = 1;
			break;
		case 2:
			new_worker->proxy_flag = 2;
			new_worker->proxy = arg;
			break;
		default:
			fprintf(stderr, "[-] Wrong proxy flag.\n");
	}
	
	/* add to wait queue list. */
	pthread_mutex_lock(&(thread_pool->queue_lock));
	wlist_add(&(new_worker->list), &(thread_pool->worker_list_head));
	thread_pool->curr_worker_num++;
	pthread_mutex_unlock(&(thread_pool->queue_lock));

	pthread_cond_signal(&(thread_pool->queue_ready));

	return 1;
}

void print_worker_list(void)
{
	THREAD_WORKER *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, ((&(thread_pool->worker_list_head)))) {
		s = list_entry(p, THREAD_WORKER, list);
		if (s) {
			fprintf(stderr, "[*] %d, %d, %d\n", 
				s->ip, s->port, s->proxy_flag);
		}
	}
}

void *worker_thread(void *arg)
{
	THREAD_WORKER *worker = NULL;

	for (;;) {
		/* Get the lock and try to check the current
  		 * queue num is not NULL. */
		pthread_mutex_lock(&(thread_pool->queue_lock));
		while (!thread_pool->curr_worker_num &&
			!thread_pool->destroy_flag) {
			pthread_cond_wait(&(thread_pool->queue_ready),
				&(thread_pool->queue_lock));
		}

		/* Start to destroy thread pool */
		if (thread_pool->destroy_flag == 1) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			break;
		}

		/* Get a worker from the queue. */
		worker = list_entry((&(thread_pool->worker_list_head))->next,
			THREAD_WORKER, list);		
		if (!worker) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			continue;
		}

		wlist_del(((&(thread_pool->worker_list_head))->next));
		thread_pool->curr_worker_num--;
		pthread_mutex_unlock(&(thread_pool->queue_lock));

		if (worker->tcp_scan_port) {
			worker->tcp_scan_port(worker->ip, worker->port,
				worker->proxy_flag, worker->proxy);
			free(worker);
		}
		worker = NULL;
	}
}

int destroy_thread_pool(void)
{
	int i;

	/* set the destroy flag. */
	pthread_mutex_lock(&(thread_pool->queue_lock));
	thread_pool->destroy_flag = 1;
	pthread_mutex_unlock(&(thread_pool->queue_lock));

	/* call all wait threads. */
	pthread_cond_broadcast(&(thread_pool->queue_ready));

	/* wait threads to finsh. */
	for (i = 0; i < thread_pool->max_thread_num; i++) {
		if (pthread_join(thread_pool->thread_id[i], NULL) != 0) {
			perror("thread_join");
			return 0;
		}
		fprintf(stderr, "[+] Join thread %d ok.\n", i);
	}
	
	pthread_mutex_destroy(&(thread_pool->queue_lock));
	pthread_cond_destroy(&(thread_pool->queue_ready));

	/* free list memory. */
	FREE_LIST(THREAD_WORKER, (thread_pool->worker_list_head))
	FREE_LIST(PROXY, proxy_list_head);

	thread_pool = NULL;
	fprintf(stderr, "[+] Wait all threads ok.\n");

	return 1;
}

void wait_all_thread_finsh(void)
{
	for (;;) {
		pthread_mutex_lock(&(thread_pool->queue_lock));
		if (thread_pool->curr_worker_num == 0 &&
			add_all_worker_flag == 1) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			destroy_thread_pool();
			break;
		}
		pthread_mutex_unlock(&(thread_pool->queue_lock));
		usleep(20);
	}
}

void test_queue_num(void)
{
	for (;;) {
		pthread_mutex_lock(&(thread_pool->queue_lock));
		if (thread_pool->curr_worker_num == MAX_QUEUE_NUM) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			usleep(5);
		}
		pthread_mutex_unlock(&(thread_pool->queue_lock));
		break;
	}
}

int init_socks5_list(void)
{
	SOCKS5_PROXY *socks5_proxy = NULL;
	int i;

	INIT_LIST_HEAD(&socks5_list_head);
	pthread_mutex_init(&list_lock, NULL);

	for (i = 1; i <= 5; i++) {
		socks5_proxy = (SOCKS5_PROXY *)malloc(sizeof(SOCKS5_PROXY));
		if (!socks5_proxy) {
			fprintf(stderr, "Malloc failed.\n");
			return 0;
		}
		
		socks5_proxy->proxy_id = i;	
		socks5_proxy->flag = 2;	
		strcpy(socks5_proxy->proxy_ip, "127.0.0.1");
		socks5_proxy->port = 1080 + i;	
		socks5_proxy->max_port_num = 2;	
		socks5_proxy->curr_run_num = 0;	
		socks5_proxy->max_run_num = 65535;	

		pthread_mutex_init(&(socks5_proxy->socks5_lock), NULL);
		wlist_add_tail(&(socks5_proxy->list), &socks5_list_head);
	}
		
	return 1;
}

void print_socks5_list(void)
{
	SOCKS5_PROXY *s = NULL;
	struct list_head *p = NULL;

	printf("\n----------------------------\n");
	list_for_each(p, (&socks5_list_head)) {
		s = list_entry(p, SOCKS5_PROXY, list);
		if (s) {
			fprintf(stderr, "%d\n%s\n%d\n%d\n%d\n%d\n\n",
				s->proxy_id, s->proxy_ip,
				s->port, s->max_port_num,
				s->curr_run_num, s->max_run_num);
		}
	}
}

/**
 * search the socks5 list, and find out the least curr_run_num value,
 * and then return the socks5_proxy pointer.
 */
SOCKS5_PROXY *__select_socks5_proxy(void)
{
	SOCKS5_PROXY *socks5_proxy = NULL;
	SOCKS5_PROXY *p = NULL;
	struct list_head *s = NULL;
	int min;

	/* Before get the socks5_proxy struct's lock, 
	 * we use socks5 queue list lock to lock the first 
	 * socks5_proxy struct. */
	pthread_mutex_lock(&list_lock);
	socks5_proxy = list_entry((&socks5_list_head)->next, SOCKS5_PROXY, 
		list); 
	if (!socks5_proxy) {
		fprintf(stderr, "[-] Socks5 list is NULL?\n");
		pthread_mutex_unlock(&list_lock);
		return NULL;
	}
		
	/* now we got the socks5_proxy struct's lock.*/
	pthread_mutex_lock(&(socks5_proxy->socks5_lock));
	min = socks5_proxy->curr_run_num;
	p = socks5_proxy;
	DbgPrint("!proxy_id: %d\t->min: %d, curr: %d\n", p->proxy_id, min, 
		p->curr_run_num);
	pthread_mutex_unlock(&(socks5_proxy->socks5_lock));

	/* find the least value of curr_run_num. */
	list_for_each(s, (&socks5_list_head)) {
		socks5_proxy = list_entry(s, SOCKS5_PROXY, list);
		if (socks5_proxy) {
			/* use socks5_proxy lock everytime. */
			pthread_mutex_lock(&(socks5_proxy->socks5_lock));
			DbgPrint("proxy_id: %d, curr_num: %d\n", 
				socks5_proxy->proxy_id, 
				socks5_proxy->curr_run_num);
			if (socks5_proxy->curr_run_num < min) {
				DbgPrint("min: %d, curr_num: %d\n", min, 
					socks5_proxy->curr_run_num);
				min = socks5_proxy->curr_run_num;	
				p = socks5_proxy;
			}
			pthread_mutex_unlock(&(socks5_proxy->socks5_lock));
		}
	}

	pthread_mutex_lock(&(p->socks5_lock));
	p->curr_run_num++;
	DbgPrint("!!proxy_id: %d\t->min: %d, curr: %d, max_run_num: %d\n", 
		p->proxy_id, min, p->curr_run_num, p->max_run_num);
	pthread_mutex_unlock(&(p->socks5_lock));
	pthread_mutex_unlock(&list_lock);
	
	return p;
}

SOCKS5_PROXY *select_socks5_proxy(void)
{
	SOCKS5_PROXY *s = NULL;

	s = __select_socks5_proxy();
	if (!s) {
		return NULL;
	}

	/* Not have good idea this version :D */
	for (;;) {
		pthread_mutex_lock(&(s->socks5_lock));
		if (s->curr_run_num > s->max_run_num) {
			pthread_mutex_unlock(&(s->socks5_lock));
			printf("select socks5 proxy sleep ...\n");
			usleep(30);
			s = __select_socks5_proxy();
			continue;
		}
		pthread_mutex_unlock(&(s->socks5_lock));
		break;
	}

	return s;
}

void parse_scan_type(char *type)
{
	if (!strcmp(type, "port")) {
		scan_fn = tcp_scan_port;
	}	
	if (!strcmp(type, "pass")) {
		scan_fn = tcp_scan_port;
	}	
	if (!strcmp(type, "web")) {
		scan_fn = tcp_scan_port;
	}	
}

/**
 * Add all scan ip and ports to the wait queue.
 */
void *add_all_worker_thread(void *arg)
{
	PROXY *new_proxy = NULL;
	SOCKS5_PROXY *socks5_proxy = NULL;
	unsigned int start_ip, end_ip;
	unsigned int start_port, end_port;
	unsigned int tmp_ip, tmp_port;
	unsigned int ip;
	int port_num;
	int flag;

	INIT_LIST_HEAD(&proxy_list_head);

	start_ip = ntohl(inet_addr(g_scan_arg.start_ip));
	end_ip = ntohl(inet_addr(g_scan_arg.end_ip));
	start_port = g_scan_arg.start_port;
	end_port = g_scan_arg.end_port;

	for (tmp_ip = start_ip; tmp_ip <= end_ip; tmp_ip++) {
		ip = htonl(tmp_ip); port_num = 0;;

		/* Use one proxy struct to each ip. */
		switch (g_proxy_flag) {
		case 2:
			socks5_proxy = select_socks5_proxy();
                	new_proxy = (PROXY *)malloc(sizeof(PROXY));
                	if (!new_proxy) {
      	        		fprintf(stderr, "Malloc failed.\n");
                        	return ;
                	}

               		new_proxy->id = socks5_proxy->proxy_id;
                	strcpy(new_proxy->ip, socks5_proxy->proxy_ip);
                	new_proxy->port = socks5_proxy->port;
                	new_proxy->flag = socks5_proxy->flag;
			wlist_add_tail(&(new_proxy->list), &proxy_list_head);
			break;
		}

		for (tmp_port = start_port; tmp_port <= end_port; 
			tmp_port++, port_num++) {
			test_queue_num();
			switch (g_proxy_flag) {
			case 0:
				add_worker(NULL, scan_fn, ip, 
					htons(tmp_port));
				break;
			case 1:
				break;
			case 2:
				socks5_proxy = select_socks5_proxy();

				/* If the ip limited the max scanned ports,
				 * select new proxy to scan it.*/
				if ((port_num >= socks5_proxy->max_port_num) 
					&& (port_num % 
					socks5_proxy->max_port_num == 0)) {
					fprintf(stderr, 
						"[+] %d, %d Select new socks5 proxy.\n", 
						tmp_port, port_num);
					socks5_proxy = 
						select_socks5_proxy();
					free(new_proxy);
					new_proxy = NULL;
                                	new_proxy = (PROXY *)malloc(sizeof(PROXY));
                                	if (!new_proxy) {
                                        	fprintf(stderr, "Malloc failed.\n");
                                        	return ;
                                	}

                                	new_proxy->id = socks5_proxy->proxy_id;
                                	strcpy(new_proxy->ip, 
						socks5_proxy->proxy_ip);
                                	new_proxy->port = socks5_proxy->port;
                                	new_proxy->flag = socks5_proxy->flag;
					wlist_add_tail(&(new_proxy->list), 
						&proxy_list_head);
				}

				DbgPrint("%d: socks5 proxy: %d\t%s:%d, %d %d\n", 
					tmp_port,
					socks5_proxy->proxy_id,
					socks5_proxy->proxy_ip,
					socks5_proxy->port,
					socks5_proxy->max_port_num,
					socks5_proxy->max_run_num);
				/* add it to wait queue. */
				add_worker((void *)new_proxy, scan_fn, 
					ip, htons(tmp_port));
				break;
			default:
				fprintf(stderr, "[-] Wrong proxy flag.\n");
				return ;
			}
		}
	}

	/* This flag is very important. The destroy thread will use it. */
	add_all_worker_flag = 1;
	fprintf(stderr, "[+] Add all worker finshed.\n");
}

int start_add_worker_thread(void)
{
	pthread_t id;

	if (pthread_create(&id, NULL, add_all_worker_thread, NULL) != 0) {
		perror("thread_create");
		return 0;
	}
	fprintf(stderr, "[+] Start add worker thread ok.\n");

	return 1;
}
