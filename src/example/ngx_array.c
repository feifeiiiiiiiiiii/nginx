#include "ngx_array.h"

ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size) {
  ngx_array_t *a;

  a = ngx_palloc(p, sizeof(ngx_array_t));
  if (a == NULL) {
    return NULL;
  }

  if (ngx_array_init(a, p, n, size) != 0) {
    return NULL;
  }
  return a;
}

void ngx_array_destroy(ngx_array_t *a) {
  ngx_pool_t *p;

  p = a->pool;

  if((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
    p->d.last -= a->size * a->nalloc;
  }

  if((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
    p->d.last = (u_char *)a;
  }
}
