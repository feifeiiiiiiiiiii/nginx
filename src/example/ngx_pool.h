#ifndef _NGX_POOL_H_INCLUDED_
#define _NGX_POOL_H_INCLUDED_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define u_char uint8_t
typedef struct ngx_pool_s        ngx_pool_t;

typedef struct {
  u_char        *last;
  u_char        *end;
  ngx_pool_t    *next;
} ngx_pool_data_t;

struct ngx_pool_s {
  ngx_pool_data_t     d;
  size_t              max;
  ngx_pool_t          *current;
};

ngx_pool_t *ngx_create_pool(size_t size);
void *ngx_palloc(ngx_pool_t *pool, size_t size);

#endif /* NGX_POOL_H_INCLUDE_ */
