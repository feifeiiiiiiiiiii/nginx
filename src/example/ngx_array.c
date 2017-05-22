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

void *ngx_array_push(ngx_array_t *a) {
  void *elt, *new;
  size_t size;
  ngx_pool_t *p;

  if (a->nelts == a ->nalloc) {
    size = a->size * a->nalloc;
    p = a->pool;

    if((u_char *)a->elts + size == p->d.last &&
        p->d.last + a->size <= p->d.end) {
          p->d.last += a->size;
          a->nalloc++;
    } else {
      new = ngx_palloc(p, 2 * size);
      if (new == NULL) {
        return NULL;
      }
      memcpy(new, a->elts, size);
      a->elts = new;
      a->nalloc *= 2;
    }
  }
  elt = (u_char *)a->elts + a->size * a->nelts;
  a->nelts++;
  return elt;
}
