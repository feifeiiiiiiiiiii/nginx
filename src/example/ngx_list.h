#ifndef NGX_LIST_H_INCLUDE_
#define NGX_LIST_H_INCLUDE_

#include "ngx_pool.h"

typedef struct ngx_list_part_s ngx_list_part_t;

struct ngx_list_part_s {
  void *elts;
  ngx_uint_t nelts;
  ngx_list_part_t *next;
};

typedef struct {
  ngx_list_part_t *last;
  ngx_list_part_t part;
  size_t size;
  ngx_uint_t nalloc;
  ngx_pool_t *pool;
} ngx_list_t;

ngx_list_t *ngx_create_list(ngx_pool_t *pool, ngx_uint_t n, size_t size);
void *ngx_list_push(ngx_list_t *list);

static inline ngx_int_t ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size) {
  list->part.elts = ngx_palloc(pool, n * size);
  if (list->part.elts == NULL) {
    return -1;
  }

  list->part.nelts = 0;
  list->part.next = NULL;
  list->last = &list->part;
  list->size = size;
  list->nalloc = n;
  list->pool = pool;

  return 0;
}

#endif /* NGX_LIST_H_INCLUDE_ */
