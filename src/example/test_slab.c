#include "ngx_slab.h"

int main() {
	ngx_slab_pool_t *pool;
	int i;

	pool = (ngx_slab_pool_t *)malloc(1024 * 1024 * 10);
	if(pool == NULL) {
		printf("malloc 10M failed\n");
		return -1;
	}
	pool->min_shift = 3;
	ngx_slab_init(pool);
	for(i = 0; i < 505; ++i) {
		ngx_slab_alloc_locked(pool, 4);
	}
	return 0;
}
