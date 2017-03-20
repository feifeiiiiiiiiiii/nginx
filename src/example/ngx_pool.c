#include "ngx_pool.h"

static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);

ngx_pool_t *ngx_create_pool(size_t size) {
  ngx_pool_t *p;

  p = malloc(size);

  if(p == NULL) {
    return NULL;
  }

  p->d.last = (u_char *) p + sizeof(ngx_pool_t);
  p->d.end = (u_char *) p + size;
  p->d.next = NULL;

  p->current = p;

  return p;
}

void *ngx_palloc(ngx_pool_t *pool, size_t size) {
  u_char *m;
  ngx_pool_t *p;

  p = pool->current;

  do {
    // NGX 会对分配的内存进行对齐使用 这里忽略
    if ((size_t) (p->d.end - p->d.last) >= size) {
      p->d.last = p->d.last + size;
      return p->d.last - size;
    }
    p = p->d.next;
  } while(p);

  return ngx_palloc_block(pool, size);
}

static void *ngx_palloc_block(ngx_pool_t *pool, size_t size) {
  u_char *m;
  size_t psize;
  ngx_pool_t *p, *new;

  psize = (size_t)(pool->d.end - (u_char *) pool);

  m = malloc(psize);

  if(m == NULL) {
    return NULL;
  }

  new = (ngx_pool_t *) m;

  new->d.end = m + psize;
  new->d.next = NULL;

  m += sizeof(ngx_pool_data_t);

  new->d.last = m + size;

  p->d.next = new;
  return m;
}
