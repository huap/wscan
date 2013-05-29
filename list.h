#ifndef LIST_H
#define LIST_H

#include <stddef.h>

struct list_head {
        struct list_head *prev, *next;
};


#define INIT_LIST_HEAD(name_ptr)        do {    (name_ptr)->next = (name_ptr);  \
                                                (name_ptr)->prev = (name_ptr);  \
                                        }while (0)


#define OFFSET(type, member)            (char *)&(((type *)0x0)->member)

/*
#define container_of(ptr, type, member) ({                                      \
                        (type *)((char * )ptr - OFFSET(type, member)); });
*/
/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:    the pointer to the member.
 * @type:    the type of the container struct this is embedded in.
 * @member:    the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({    \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member));})

#define list_for_each(pos, head)        for (pos = head->next; pos != head; pos = pos->next)
#define list_for_each_prev(pos, head)   for (pos = head->prev; pos != head; pos = pos->prev)
#define list_entry(ptr, type, member)   container_of(ptr, type, member)

static inline void wlist_add_tail(struct list_head *new_node, struct list_head *head)
{
        head->prev->next = new_node;
        new_node->prev = head->prev;
        new_node->next = head;
        head->prev = new_node;
}

static inline void wlist_add_tail1(struct list_head *new_node, struct list_head *head)
{
        new_node->next = head;
        new_node->prev = head->prev;
        head->prev->next = new_node;
        head->prev = new_node;
}

static inline void wlist_add(struct list_head *new_node, struct list_head *head)
{
        new_node->next = head->next;
        new_node->prev = head;
        head->next->prev = new_node;
        head->next = new_node;
}

static inline void wlist_del(struct list_head *p)
{
        p->prev->next = p->next;
        p->next->prev = p->prev;
}

static inline int wlist_empty(struct list_head *head)
{
        return head->next == head;
}

#define FREE_LIST(type, link_head) {                            \
        type *p = NULL;                                         \
        struct list_head *s = NULL;                             \
        struct list_head *q = NULL;                             \
        for (s = (&link_head)->next; s != &link_head; s = q) {  \
                if (!s)                                         \
                        return ;                                \
                q = s->next;                                    \
                p = list_entry(s, type, list);                  \
                if (p) {                                        \
                        wlist_del(s);                           \
                        free(p);                                \
                        p = NULL;                               \
                }                                               \
        }}

#endif
