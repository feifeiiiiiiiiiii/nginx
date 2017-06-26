#ifndef NGX_SLAB_H_
#define NGX_SLAB_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define u_char uint8_t
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;

#define ngx_pagesize 4096

#define u_char uint8_t


typedef struct ngx_slab_page_s  ngx_slab_page_t;

struct ngx_slab_page_s {
    uintptr_t         slab;
    ngx_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {

    size_t            min_size;
    size_t            min_shift;

    ngx_slab_page_t  *pages;
    ngx_slab_page_t  *last;
    ngx_slab_page_t   free;

    u_char           *start;
    u_char           *end;

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} ngx_slab_pool_t;

void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);

#endif /* */