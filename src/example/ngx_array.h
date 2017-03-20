#ifndef _NGX_ARRAY_H_INCLUDE_
#define _NGX_ARRAY_H_INCLUDE_

#include "ngx_pool.h"

typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;

typedef struct {
  void          *elts;
  ngx_uint_t    nelts;
  size_t        size;
  ngx_uint_t    nalloc;
  ngx_pool_t    *pool;
} ngx_array_t;

ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
void ngx_array_destory(ngx_array_t *a);

static ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size) {
  array->nelts = 0;
  array->size = size;
  array->nalloc = n;
  array->pool = pool;

  array->elts = ngx_palloc(pool, n * size);
  if (array->elts == NULL) {
    return -1;
  }
  return 0;
}

#endif /* _NGX_ARRAY_H_INCLUDE_ */
