#include "ngx_array.h"

int main() {
  ngx_pool_t *pool;
  ngx_array_t *arr;

  pool = ngx_create_pool(1000);

  arr = ngx_array_create(pool, 10, sizeof(int));
  for(int i = 0; i < 1000; ++i) {
    int *elt = ngx_array_push(arr);
    *elt = i;
  }
  int *ptr = arr->elts;
  for(int i = 0; i < arr->nelts; ++i) {
    printf("%d\n", *ptr+i);
  }
  return 0;
}
