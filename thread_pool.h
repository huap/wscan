#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#define MAX_THREAD_NUM		5
#define MAX_QUEUE_NUM		10

typedef struct thread_worker_st {
	int (*tcp_scan_port)(unsigned int, unsigned int, int, void *);
	int (*web_content_scan)(unsigned int, unsigned int, int, void *);
	unsigned int ip;
	unsigned int port;
	int proxy_flag;
	void *proxy;
	struct list_head list;
}THREAD_WORKER;

typedef struct thread_pool_st {
	pthread_t *thread_id;
	pthread_mutex_t queue_lock;
	pthread_cond_t queue_ready;
	struct list_head worker_list_head;
	int destroy_flag;
	int max_thread_num;
	int curr_worker_num;
}THREAD_POOL;

int init_thread_pool(int thread_num);
int add_worker(void *arg, int (*fn)(unsigned int, unsigned int, int, void *),
                unsigned int ip, unsigned int port);
void print_worker_list(void);
void *worker_thread(void *arg);
int destroy_thread_pool(void);
void wait_all_thread_finsh(void);
int init_socks5_list(void);
void *add_all_worker_thread(void *arg);
int start_add_worker_thread(void);

#endif
