#include "ngx_array.h"
#include "ngx_list.h"

int main() {
  ngx_pool_t *pool;
  ngx_array_t *arr;

  pool = ngx_create_pool(1000);

  printf("ngx_array start\n");
  arr = ngx_array_create(pool, 10, sizeof(int));
  for(int i = 0; i < 1000; ++i) {
    int *elt = ngx_array_push(arr);
    *elt = i;
  }
  int *ptr = arr->elts;
  for(int i = 0; i < arr->nelts; ++i) {
    printf("%d ", *ptr+i);
  }
  printf("\nngx_array end\n\n");
  printf("ngx_list start\n");

  ngx_list_t *list;
  list = ngx_create_list(pool, 10, sizeof(int));

  for(int i = 0; i < 1000; ++i) {
    int *ptr = ngx_list_push(list);
    *ptr = i;
  }

  ngx_list_part_t *part = &list->part;
  int *data = part->elts;
  int i;

  for(i = 0;; i++) {
    if(i >= part->nelts) {
      if (part->next == NULL) break;
      part = part->next;
      data = part->elts;
      i = 0;
    }
    printf("%d ", *data + i);
  }
  printf("\nngx_list end\n");

  return 0;
}
