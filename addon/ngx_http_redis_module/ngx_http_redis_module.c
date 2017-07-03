
#line 1 "ngx_http_redis_module.rl"
// COPY https://github.com/openresty/redis2-nginx-module
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_redis_ctx_s  ngx_http_redis_ctx_t;

typedef ngx_int_t (*ngx_http_redis_filter_handler_ptr)
    (ngx_http_redis_ctx_t *ctx, ssize_t bytes);

struct ngx_http_redis_ctx_s {
	ngx_http_request_t *request;
    int                 state;
    size_t              chunk_size;
    size_t              chunk_bytes_read;
    size_t              chunks_read;
    size_t              chunk_count;
    ngx_http_redis_filter_handler_ptr filter;
};

typedef struct {
  ngx_http_upstream_conf_t   upstream;
	ngx_array_t *queries;
} ngx_http_redis_loc_conf_t;

static void *ngx_http_redis_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_redis_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_redis_query(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_redis_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_process_reply(ngx_http_redis_ctx_t *ctx, ssize_t bytes);

static ngx_int_t ngx_http_redis_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_filter_init(void *data);
static ngx_int_t ngx_http_redis_filter(void *data, ssize_t bytes);
static void ngx_http_redis_abort_request(ngx_http_request_t *r);
static void ngx_http_redis_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_command_t ngx_http_redis_commands[] = {
	{ ngx_string("redis_pass"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_http_redis_pass,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	{ ngx_string("redis_query"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
		ngx_http_redis_query,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_redis_module_ctx = {
	NULL,
	NULL,

	NULL,
	NULL,

	NULL,
	NULL,

	ngx_http_redis_create_loc_conf,
	ngx_http_redis_merge_loc_conf
};

ngx_module_t ngx_http_redis_module  = {
	NGX_MODULE_V1,
	&ngx_http_redis_module_ctx,
	ngx_http_redis_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
  NGX_MODULE_V1_PADDING
};

static void *
ngx_http_redis_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_redis_loc_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_redis_loc_conf_t));

	if (conf == NULL) {
		return NULL;
	}

	conf->upstream.local = NGX_CONF_UNSET_PTR;
	conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
	conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

	conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

	/* the hardcoded values */
	conf->upstream.cyclic_temp_file = 0;
	conf->upstream.buffering = 0;
	conf->upstream.ignore_client_abort = 0;
	conf->upstream.send_lowat = 0;
	conf->upstream.bufs.num = 0;
	conf->upstream.busy_buffers_size = 0;
	conf->upstream.max_temp_file_size = 0;
	conf->upstream.temp_file_write_size = 0;
	conf->upstream.intercept_errors = 1;
	conf->upstream.intercept_404 = 1;
	conf->upstream.pass_request_headers = 0;
	conf->upstream.pass_request_body = 0;
	return conf;
}

static char *
ngx_http_redis_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_redis_loc_conf_t *prev = parent;
	ngx_http_redis_loc_conf_t *conf = child;

	ngx_conf_merge_ptr_value(conf->upstream.local,
			prev->upstream.local, NULL);

	ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
			prev->upstream.next_upstream_tries, 0);

	ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
			prev->upstream.connect_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.send_timeout,
			prev->upstream.send_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.read_timeout,
			prev->upstream.read_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
			prev->upstream.next_upstream_timeout, 0);

	ngx_conf_merge_size_value(conf->upstream.buffer_size,
			prev->upstream.buffer_size,
			(size_t) ngx_pagesize);

	ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
			prev->upstream.next_upstream,
			(NGX_CONF_BITMASK_SET
			 |NGX_HTTP_UPSTREAM_FT_ERROR
			 |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

	if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
		conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
			|NGX_HTTP_UPSTREAM_FT_OFF;
	}

	if (conf->upstream.upstream == NULL) {
		conf->upstream.upstream = prev->upstream.upstream;
	}
	return NGX_CONF_OK;
}

static char *
ngx_http_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_redis_loc_conf_t *rlcf = conf;
  ngx_str_t                 *value;
  ngx_http_core_loc_conf_t  *clcf;
  ngx_url_t                  url;

  if(rlcf->upstream.upstream) {
    return "is duplicate";
  }

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

  clcf->handler = ngx_http_redis_handler;

  if (clcf->name.data[clcf->name.len - 1] == '/') {
    clcf->auto_redirect = 1;
  }

  value = cf->args->elts;

  ngx_memzero(&url, sizeof(ngx_url_t));
  url.url = value[1];
  url.no_resolve = 1;

  rlcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0);
  if (rlcf->upstream.upstream == NULL) {
    return NGX_CONF_ERROR;
  }

	return NGX_CONF_OK;
}

static char *
ngx_http_redis_query(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_redis_loc_conf_t *rlcf = conf;
	ngx_array_t 							**query;
	ngx_http_complex_value_t  **arg;
  ngx_str_t                   *value;
	ngx_uint_t 									i;
  ngx_uint_t                  n;

  ngx_http_compile_complex_value_t         ccv;

	if(rlcf->queries == NULL) {
			rlcf->queries = ngx_array_create(cf->pool, 1, sizeof(ngx_array_t *));
			if(rlcf->queries == NULL) {
				return NGX_CONF_ERROR;
			}
	}

	query = ngx_array_push(rlcf->queries);

	if(query == NULL) {
		return NGX_CONF_ERROR;
	}

	n = cf->args->nelts - 1;

	*query = ngx_array_create(cf->pool, n, sizeof(ngx_http_complex_value_t *));
	if(*query == NULL) {
		return NGX_CONF_ERROR;
	}

	value = cf->args->elts;

	for(i = 1; i <= n; ++i) {
		arg = ngx_array_push(*query);
		if(arg == NULL) {
			return NGX_CONF_ERROR;
		}

		*arg = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
		if(*arg == NULL) {
			return NGX_CONF_ERROR;
		}

		if(value[i].len == 0) {
			ngx_memzero(*arg, sizeof(ngx_http_complex_value_t));
			continue;
		}

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = &value[i];
		ccv.complex_value = *arg;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Header filter add header %s", value[i].data);
		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_redis_handler(ngx_http_request_t *r)
{
  ngx_int_t                   rc;
  ngx_http_upstream_t         *u;
  ngx_http_redis_ctx_t        *ctx;
  ngx_http_redis_loc_conf_t   *rlcf;

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK) {
		return rc;
	}

	if (ngx_http_set_content_type(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_http_upstream_create(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	u = r->upstream;

	ngx_str_set(&u->schema, "redis://");
	u->output.tag = (ngx_buf_tag_t) &ngx_http_redis_module;
	rlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);
	u->conf = &rlcf->upstream;

	u->create_request = ngx_http_redis_create_request;
	u->reinit_request = ngx_http_redis_reinit_request;
	u->process_header = ngx_http_redis_process_header;
	u->abort_request = ngx_http_redis_abort_request;
	u->finalize_request = ngx_http_redis_finalize_request;

	ctx = ngx_palloc(r->pool, sizeof(ngx_http_redis_ctx_t));
	if(ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->request = r;
    ctx->state = NGX_ERROR;

	ngx_http_set_ctx(r, ctx, ngx_http_redis_module);

	u->input_filter_init = ngx_http_redis_filter_init;
	u->input_filter = ngx_http_redis_filter;
	u->input_filter_ctx = ctx;

	r->main->count++;

	ngx_http_upstream_init(r);

  return NGX_DONE;
}

static ngx_int_t
ngx_http_redis_create_request(ngx_http_request_t *r)
{
	ngx_http_redis_loc_conf_t *rlcf;
	ngx_buf_t									*b;
 	ngx_chain_t               *cl;
	ngx_str_t str = ngx_string("*2\r\n$3\r\nGET\r\n$3\r\nabc\r\n");

	rlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);

 	b = ngx_create_temp_buf(r->pool, str.len);
	if(b == NULL) {
		return NGX_ERROR;
	}

	if(rlcf->queries) {
	}

	b->pos = str.data;
	b->last = b->pos + str.len;
	b->memory = 1;

	cl = ngx_alloc_chain_link(r->pool);
	if(cl == NULL) {
		return NGX_ERROR;
	}
	cl->buf = b;
	cl->next = NULL;
	r->upstream->request_bufs = cl;
	return NGX_OK;
}

static ngx_int_t
ngx_http_redis_reinit_request(ngx_http_request_t *r)
{
	return NGX_OK;
}

static ngx_int_t
ngx_http_redis_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t         *u;
    ngx_buf_t                   *b;
    u_char                       chr;

    ngx_http_redis_ctx_t 				*ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_redis_module);

    u = r->upstream;
    b = &u->buffer;

    if (b->last - b->pos < (ssize_t) sizeof(u_char)) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "process header");
        return NGX_AGAIN;
    }

    chr = *b->pos;

    // handler
    switch(chr) {
        case '+':
        case '-':
        case ':':
        case '$':
        case '*':
            ctx->filter = ngx_http_redis_process_reply;
            break;
        default:
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "invalid header");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    u->headers_in.status_n = NGX_HTTP_OK;
    u->state->status = NGX_HTTP_OK;

    return NGX_OK;
}

static ngx_int_t
ngx_http_redis_filter_init(void *data)
{
	return NGX_OK;
}

static ngx_int_t
ngx_http_redis_filter(void *data, ssize_t bytes)
{
    ngx_http_redis_ctx_t  *ctx = data;

    return ctx->filter(ctx, bytes);
}

static void
ngx_http_redis_abort_request(ngx_http_request_t *r)
{
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "abort_request");
  return;
}

static void
ngx_http_redis_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "finalize request");
  if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    r->headers_out.status = rc;
  }
  return;
}


#line 520 "ngx_http_redis_module.rl"



#line 444 "ngx_http_redis_module.c"
static const int rdsreply_start = 1;
static const int rdsreply_first_final = 44;
static const int rdsreply_error = 0;

static const int rdsreply_en_main = 1;


#line 523 "ngx_http_redis_module.rl"

static ngx_int_t
ngx_http_redis_process_reply(ngx_http_redis_ctx_t *ctx, ssize_t bytes)
{
    int cs;
    ngx_buf_t *b;
    ngx_http_upstream_t *u;
    ngx_str_t buf;
    signed char *p;
    signed char *pe;
    signed char              *orig_p;
    ssize_t                   orig_len;
    int done = 0;

    ngx_chain_t *cl = NULL;
    ngx_chain_t **ll = NULL;

    u = ctx->request->upstream;
    b = &u->buffer;

    if(ctx->state == NGX_ERROR) {
        
#line 475 "ngx_http_redis_module.c"
	{
	cs = rdsreply_start;
	}

#line 545 "ngx_http_redis_module.rl"
        ctx->state = cs;
    } else {
        cs = ctx->state;
    }

    orig_p = (signed char *)b->last;
    orig_len = bytes;

    p = (signed char *) b->last;
    pe = (signed char *) b->last + bytes;

    
#line 493 "ngx_http_redis_module.c"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	switch( (*p) ) {
		case 36: goto st2;
		case 42: goto st12;
		case 43: goto st42;
		case 45: goto st42;
		case 58: goto st42;
	}
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	switch( (*p) ) {
		case 45: goto st3;
		case 48: goto st4;
	}
	if ( 49 <= (*p) && (*p) <= 57 )
		goto tr6;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr7;
	goto st0;
tr7:
#line 453 "ngx_http_redis_module.rl"
	{
        done = 1;
    }
	goto st44;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
#line 540 "ngx_http_redis_module.c"
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr7;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	switch( (*p) ) {
		case 13: goto st5;
		case 48: goto st4;
	}
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 10 )
		goto tr9;
	goto st0;
tr9:
#line 453 "ngx_http_redis_module.rl"
	{
        done = 1;
    }
	goto st45;
tr16:
#line 444 "ngx_http_redis_module.rl"
	{
        ctx->chunks_read++;
    }
#line 453 "ngx_http_redis_module.rl"
	{
        done = 1;
    }
	goto st45;
tr23:
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st45;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
#line 588 "ngx_http_redis_module.c"
	goto st0;
tr6:
#line 439 "ngx_http_redis_module.rl"
	{
        ctx->chunk_bytes_read = 0;
        ctx->chunk_size = 0;
    }
#line 448 "ngx_http_redis_module.rl"
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }
	goto st6;
tr11:
#line 448 "ngx_http_redis_module.rl"
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 613 "ngx_http_redis_module.c"
	if ( (*p) == 13 )
		goto st7;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr11;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 10 )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	_widec = (*p);
	_widec = (short)(128 + ((*p) - -128));
	if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
	if ( 384 <= _widec && _widec <= 639 )
		goto st9;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(128 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(128 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		}
	} else {
		_widec = (short)(1152 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
	}
	switch( _widec ) {
		case 1549: goto st9;
		case 1805: goto st10;
		case 2061: goto st11;
	}
	if ( _widec > 524 ) {
		if ( 526 <= _widec && _widec <= 639 )
			goto st9;
	} else if ( _widec >= 384 )
		goto st9;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 10 )
		goto tr16;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(128 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(128 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		}
	} else {
		_widec = (short)(1152 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
	}
	switch( _widec ) {
		case 266: goto tr16;
		case 522: goto tr17;
		case 1549: goto st9;
		case 1805: goto st10;
		case 2061: goto st11;
	}
	if ( _widec > 524 ) {
		if ( 526 <= _widec && _widec <= 639 )
			goto st9;
	} else if ( _widec >= 384 )
		goto st9;
	goto st0;
tr17:
#line 444 "ngx_http_redis_module.rl"
	{
        ctx->chunks_read++;
    }
#line 453 "ngx_http_redis_module.rl"
	{
        done = 1;
    }
	goto st46;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
#line 739 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(128 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(128 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		}
	} else {
		_widec = (short)(1152 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
	}
	switch( _widec ) {
		case 1549: goto st9;
		case 1805: goto st10;
		case 2061: goto st11;
	}
	if ( _widec > 524 ) {
		if ( 526 <= _widec && _widec <= 639 )
			goto st9;
	} else if ( _widec >= 384 )
		goto st9;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	switch( (*p) ) {
		case 45: goto st13;
		case 48: goto st16;
	}
	if ( 49 <= (*p) && (*p) <= 57 )
		goto tr20;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 49 )
		goto st14;
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	if ( (*p) == 13 )
		goto st15;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	if ( (*p) == 10 )
		goto tr23;
	goto st0;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
	switch( (*p) ) {
		case 13: goto st15;
		case 48: goto st16;
	}
	goto st0;
tr20:
#line 478 "ngx_http_redis_module.rl"
	{
        ctx->chunk_count = 0;
    }
#line 482 "ngx_http_redis_module.rl"
	{
        ctx->chunk_count *= 10;
        ctx->chunk_count += *p - '0';
    }
	goto st17;
tr25:
#line 482 "ngx_http_redis_module.rl"
	{
        ctx->chunk_count *= 10;
        ctx->chunk_count += *p - '0';
    }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 838 "ngx_http_redis_module.c"
	if ( (*p) == 13 )
		goto st18;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr25;
	goto st0;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
	if ( (*p) == 10 )
		goto tr26;
	goto st0;
tr26:
#line 487 "ngx_http_redis_module.rl"
	{
        ctx->chunks_read = 0;
    }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 861 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 43 ) {
		if ( 36 <= (*p) && (*p) <= 36 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) > 43 ) {
		if ( (*p) > 45 ) {
			if ( 58 <= (*p) && (*p) <= 58 ) {
				_widec = (short)(2176 + ((*p) - -128));
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
			}
		} else if ( (*p) >= 45 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	switch( _widec ) {
		case 2596: goto st20;
		case 2603: goto st22;
		case 2605: goto st22;
		case 2618: goto st22;
	}
	goto st0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	_widec = (*p);
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 45 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) > 48 ) {
		if ( 49 <= (*p) && (*p) <= 57 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	switch( _widec ) {
		case 2605: goto st21;
		case 2608: goto st24;
	}
	if ( 2609 <= _widec && _widec <= 2617 )
		goto tr31;
	goto st0;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
	_widec = (*p);
	if ( 48 <= (*p) && (*p) <= 57 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( 2608 <= _widec && _widec <= 2617 )
		goto tr32;
	goto st0;
tr32:
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st47;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
#line 971 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 45 ) {
		if ( (*p) > 36 ) {
			if ( 43 <= (*p) && (*p) <= 43 ) {
				_widec = (short)(2176 + ((*p) - -128));
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
			}
		} else if ( (*p) >= 36 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) > 45 ) {
		if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 58 ) {
				_widec = (short)(2176 + ((*p) - -128));
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
			}
		} else if ( (*p) >= 48 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	switch( _widec ) {
		case 2596: goto st20;
		case 2603: goto st22;
		case 2605: goto st22;
		case 2618: goto st22;
	}
	if ( 2608 <= _widec && _widec <= 2617 )
		goto tr32;
	goto st0;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( _widec == 2573 )
		goto st23;
	if ( 2432 <= _widec && _widec <= 2687 )
		goto st22;
	goto st0;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	_widec = (*p);
	if ( (*p) < 11 ) {
		if ( (*p) > 9 ) {
			if ( 10 <= (*p) && (*p) <= 10 ) {
				_widec = (short)(2176 + ((*p) - -128));
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
			}
		} else {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) > 12 ) {
		if ( (*p) > 13 ) {
			if ( 14 <= (*p) )
 {				_widec = (short)(2176 + ((*p) - -128));
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
			}
		} else if ( (*p) >= 13 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	switch( _widec ) {
		case 2570: goto tr34;
		case 2573: goto st23;
	}
	if ( 2432 <= _widec && _widec <= 2687 )
		goto st22;
	goto st0;
tr36:
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st48;
tr34:
#line 444 "ngx_http_redis_module.rl"
	{
        ctx->chunks_read++;
    }
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st48;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
#line 1142 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 43 ) {
		if ( 36 <= (*p) && (*p) <= 36 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) > 43 ) {
		if ( (*p) > 45 ) {
			if ( 58 <= (*p) && (*p) <= 58 ) {
				_widec = (short)(2176 + ((*p) - -128));
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
			}
		} else if ( (*p) >= 45 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	switch( _widec ) {
		case 2596: goto st20;
		case 2603: goto st22;
		case 2605: goto st22;
		case 2618: goto st22;
	}
	goto st0;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	_widec = (*p);
	if ( (*p) > 13 ) {
		if ( 48 <= (*p) && (*p) <= 48 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) >= 13 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	switch( _widec ) {
		case 2573: goto st25;
		case 2608: goto st24;
	}
	goto st0;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	_widec = (*p);
	if ( 10 <= (*p) && (*p) <= 10 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( _widec == 2570 )
		goto tr36;
	goto st0;
tr31:
#line 439 "ngx_http_redis_module.rl"
	{
        ctx->chunk_bytes_read = 0;
        ctx->chunk_size = 0;
    }
#line 448 "ngx_http_redis_module.rl"
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }
	goto st26;
tr38:
#line 448 "ngx_http_redis_module.rl"
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 1252 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) > 13 ) {
		if ( 48 <= (*p) && (*p) <= 57 ) {
			_widec = (short)(2176 + ((*p) - -128));
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		}
	} else if ( (*p) >= 13 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( _widec == 2573 )
		goto st27;
	if ( 2608 <= _widec && _widec <= 2617 )
		goto tr38;
	goto st0;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	_widec = (*p);
	if ( 10 <= (*p) && (*p) <= 10 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( _widec == 2570 )
		goto st28;
	goto st0;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	_widec = (*p);
	_widec = (short)(2688 + ((*p) - -128));
	if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
	if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	if ( 3456 <= _widec && _widec <= 3711 )
		goto st29;
	goto st0;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(3712 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
	}
	switch( _widec ) {
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	_widec = (*p);
	if ( 10 <= (*p) && (*p) <= 10 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( _widec == 2570 )
		goto tr34;
	goto st0;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(3712 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
	}
	switch( _widec ) {
		case 3338: goto tr34;
		case 3594: goto tr43;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
tr51:
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st49;
tr43:
#line 444 "ngx_http_redis_module.rl"
	{
        ctx->chunks_read++;
    }
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st49;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
#line 1459 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 43 ) {
		if ( (*p) < 14 ) {
			if ( (*p) > 12 ) {
				if ( 13 <= (*p) && (*p) <= 13 ) {
					_widec = (short)(3712 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
				}
			} else {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 35 ) {
			if ( (*p) > 36 ) {
				if ( 37 <= (*p) && (*p) <= 42 ) {
					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 36 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 43 ) {
		if ( (*p) < 46 ) {
			if ( (*p) > 44 ) {
				if ( 45 <= (*p) && (*p) <= 45 ) {
					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 44 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 57 ) {
			if ( (*p) > 58 ) {
				if ( 59 <= (*p) )
 {					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 58 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3364: goto st20;
		case 3371: goto st22;
		case 3373: goto st22;
		case 3386: goto st22;
		case 3620: goto st32;
		case 3627: goto st34;
		case 3629: goto st34;
		case 3642: goto st34;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	_widec = (*p);
	if ( (*p) < 45 ) {
		if ( (*p) < 13 ) {
			if ( (*p) <= 12 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 13 ) {
			if ( 14 <= (*p) && (*p) <= 44 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(3712 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
		}
	} else if ( (*p) > 45 ) {
		if ( (*p) < 48 ) {
			if ( 46 <= (*p) && (*p) <= 47 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 48 ) {
			if ( (*p) > 57 ) {
				if ( 58 <= (*p) )
 {					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 49 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3373: goto st21;
		case 3376: goto st24;
		case 3629: goto st33;
		case 3632: goto st36;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec < 3598 ) {
		if ( _widec > 3385 ) {
			if ( 3456 <= _widec && _widec <= 3596 )
				goto st29;
		} else if ( _widec >= 3377 )
			goto tr31;
	} else if ( _widec > 3631 ) {
		if ( _widec > 3641 ) {
			if ( 3642 <= _widec && _widec <= 3711 )
				goto st29;
		} else if ( _widec >= 3633 )
			goto tr46;
	} else
		goto st29;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	_widec = (*p);
	if ( (*p) < 14 ) {
		if ( (*p) > 12 ) {
			if ( 13 <= (*p) && (*p) <= 13 ) {
				_widec = (short)(3712 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 47 ) {
		if ( (*p) > 57 ) {
			if ( 58 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 48 ) {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec < 3598 ) {
		if ( _widec > 3385 ) {
			if ( 3456 <= _widec && _widec <= 3596 )
				goto st29;
		} else if ( _widec >= 3376 )
			goto tr32;
	} else if ( _widec > 3631 ) {
		if ( _widec > 3641 ) {
			if ( 3642 <= _widec && _widec <= 3711 )
				goto st29;
		} else if ( _widec >= 3632 )
			goto tr47;
	} else
		goto st29;
	goto st0;
tr47:
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st50;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
#line 1840 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 43 ) {
		if ( (*p) < 14 ) {
			if ( (*p) > 12 ) {
				if ( 13 <= (*p) && (*p) <= 13 ) {
					_widec = (short)(3712 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
				}
			} else {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 35 ) {
			if ( (*p) > 36 ) {
				if ( 37 <= (*p) && (*p) <= 42 ) {
					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 36 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 43 ) {
		if ( (*p) < 46 ) {
			if ( (*p) > 44 ) {
				if ( 45 <= (*p) && (*p) <= 45 ) {
					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 44 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 47 ) {
			if ( (*p) < 58 ) {
				if ( 48 <= (*p) && (*p) <= 57 ) {
					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) > 58 ) {
				if ( 59 <= (*p) )
 {					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3364: goto st20;
		case 3371: goto st22;
		case 3373: goto st22;
		case 3386: goto st22;
		case 3620: goto st32;
		case 3627: goto st34;
		case 3629: goto st34;
		case 3642: goto st34;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec < 3598 ) {
		if ( _widec > 3385 ) {
			if ( 3456 <= _widec && _widec <= 3596 )
				goto st29;
		} else if ( _widec >= 3376 )
			goto tr32;
	} else if ( _widec > 3631 ) {
		if ( _widec > 3641 ) {
			if ( 3643 <= _widec && _widec <= 3711 )
				goto st29;
		} else if ( _widec >= 3632 )
			goto tr47;
	} else
		goto st29;
	goto st0;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	_widec = (*p);
	if ( (*p) < 13 ) {
		if ( (*p) <= 12 ) {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 13 ) {
		if ( 14 <= (*p) )
 {			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(3712 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
	}
	switch( _widec ) {
		case 4877: goto st23;
		case 5133: goto st35;
		case 5389: goto st23;
		case 5645: goto st35;
	}
	if ( _widec < 3342 ) {
		if ( 3200 <= _widec && _widec <= 3340 )
			goto st22;
	} else if ( _widec > 3455 ) {
		if ( _widec > 3596 ) {
			if ( 3598 <= _widec && _widec <= 3711 )
				goto st34;
		} else if ( _widec >= 3456 )
			goto st34;
	} else
		goto st22;
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	_widec = (*p);
	if ( (*p) < 11 ) {
		if ( (*p) > 9 ) {
			if ( 10 <= (*p) && (*p) <= 10 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 12 ) {
		if ( (*p) > 13 ) {
			if ( 14 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 13 ) {
			_widec = (short)(3712 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3338: goto tr34;
		case 3594: goto tr43;
		case 4877: goto st23;
		case 5133: goto st35;
		case 5389: goto st23;
		case 5645: goto st35;
	}
	if ( _widec < 3342 ) {
		if ( 3200 <= _widec && _widec <= 3340 )
			goto st22;
	} else if ( _widec > 3455 ) {
		if ( _widec > 3596 ) {
			if ( 3598 <= _widec && _widec <= 3711 )
				goto st34;
		} else if ( _widec >= 3456 )
			goto st34;
	} else
		goto st22;
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	_widec = (*p);
	if ( (*p) < 14 ) {
		if ( (*p) > 12 ) {
			if ( 13 <= (*p) && (*p) <= 13 ) {
				_widec = (short)(3712 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 47 ) {
		if ( (*p) > 48 ) {
			if ( 49 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 48 ) {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3376: goto st24;
		case 3632: goto st36;
		case 4877: goto st25;
		case 5133: goto st37;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	_widec = (*p);
	if ( (*p) < 11 ) {
		if ( (*p) > 9 ) {
			if ( 10 <= (*p) && (*p) <= 10 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 12 ) {
		if ( (*p) > 13 ) {
			if ( 14 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 13 ) {
			_widec = (short)(3712 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3338: goto tr36;
		case 3594: goto tr51;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
tr46:
#line 439 "ngx_http_redis_module.rl"
	{
        ctx->chunk_bytes_read = 0;
        ctx->chunk_size = 0;
    }
#line 448 "ngx_http_redis_module.rl"
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }
	goto st38;
tr52:
#line 448 "ngx_http_redis_module.rl"
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }
	goto st38;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
#line 2348 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 14 ) {
		if ( (*p) > 12 ) {
			if ( 13 <= (*p) && (*p) <= 13 ) {
				_widec = (short)(3712 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 47 ) {
		if ( (*p) > 57 ) {
			if ( 58 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 48 ) {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 4877: goto st27;
		case 5133: goto st39;
		case 5389: goto st40;
		case 5645: goto st41;
	}
	if ( _widec < 3598 ) {
		if ( _widec > 3385 ) {
			if ( 3456 <= _widec && _widec <= 3596 )
				goto st29;
		} else if ( _widec >= 3376 )
			goto tr38;
	} else if ( _widec > 3631 ) {
		if ( _widec > 3641 ) {
			if ( 3642 <= _widec && _widec <= 3711 )
				goto st29;
		} else if ( _widec >= 3632 )
			goto tr52;
	} else
		goto st29;
	goto st0;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
	_widec = (*p);
	if ( (*p) < 11 ) {
		if ( (*p) > 9 ) {
			if ( 10 <= (*p) && (*p) <= 10 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 12 ) {
		if ( (*p) > 13 ) {
			if ( 14 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 13 ) {
			_widec = (short)(3712 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3338: goto st28;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	_widec = (*p);
	if ( 10 <= (*p) && (*p) <= 10 ) {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
	}
	if ( _widec == 2570 )
		goto tr56;
	goto st0;
tr56:
#line 444 "ngx_http_redis_module.rl"
	{
        ctx->chunks_read++;
    }
#line 495 "ngx_http_redis_module.rl"
	{
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }
	goto st51;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
#line 2544 "ngx_http_redis_module.c"
	_widec = (*p);
	if ( (*p) < 44 ) {
		if ( (*p) < 36 ) {
			if ( (*p) <= 35 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 36 ) {
			if ( (*p) > 42 ) {
				if ( 43 <= (*p) && (*p) <= 43 ) {
					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 37 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 44 ) {
		if ( (*p) < 46 ) {
			if ( 45 <= (*p) && (*p) <= 45 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) > 57 ) {
			if ( (*p) > 58 ) {
				if ( 59 <= (*p) )
 {					_widec = (short)(2688 + ((*p) - -128));
					if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
					if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
				}
			} else if ( (*p) >= 58 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3364: goto st20;
		case 3371: goto st22;
		case 3373: goto st22;
		case 3386: goto st22;
		case 3620: goto st32;
		case 3627: goto st34;
		case 3629: goto st34;
		case 3642: goto st34;
	}
	if ( 3456 <= _widec && _widec <= 3711 )
		goto st29;
	goto st0;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	_widec = (*p);
	if ( (*p) < 11 ) {
		if ( (*p) > 9 ) {
			if ( 10 <= (*p) && (*p) <= 10 ) {
				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else {
			_widec = (short)(2688 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		}
	} else if ( (*p) > 12 ) {
		if ( (*p) > 13 ) {
			if ( 14 <= (*p) )
 {				_widec = (short)(2688 + ((*p) - -128));
				if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
				if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
			}
		} else if ( (*p) >= 13 ) {
			_widec = (short)(3712 + ((*p) - -128));
			if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
			if ( 
#line 459 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read == ctx->chunk_size + 1  ) _widec += 512;
			if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
		}
	} else {
		_widec = (short)(2688 + ((*p) - -128));
		if ( 
#line 457 "ngx_http_redis_module.rl"
 ctx->chunk_bytes_read++ < ctx->chunk_size  ) _widec += 256;
		if ( 
#line 491 "ngx_http_redis_module.rl"

        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
	}
	switch( _widec ) {
		case 3338: goto tr56;
		case 3594: goto tr43;
		case 5133: goto st29;
		case 5389: goto st30;
		case 5645: goto st31;
	}
	if ( _widec > 3596 ) {
		if ( 3598 <= _widec && _widec <= 3711 )
			goto st29;
	} else if ( _widec >= 3456 )
		goto st29;
	goto st0;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	if ( (*p) == 13 )
		goto st43;
	goto st42;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	switch( (*p) ) {
		case 10: goto tr9;
		case 13: goto st43;
	}
	goto st42;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 557 "ngx_http_redis_module.rl"

    if (!done && cs == rdsreply_error) {
        if(cl) {
            cl->buf->last = cl->buf->pos;
            cl = NULL;
            *ll = NULL;
        }
        buf.data = b->pos;
        buf.len = b->last - b->pos + bytes;
        u->length = 0;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

	if (cl == NULL) {
		for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
			ll = &cl->next;
		}

		cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
		if (cl == NULL) {
			u->length = 0;
			return NGX_ERROR;
		}

		cl->buf->flush = 1;
		cl->buf->memory = 1;

		*ll = cl;

		cl->buf->pos = b->last;
		cl->buf->last = (u_char *) p;
		cl->buf->tag = u->output.tag;

	} else {
		cl->buf->last = (u_char *) p;
	}

    bytes -= (ssize_t)((u_char *)p - b->last);
    b->last = (u_char *)p;
    printf("done\n");

    if (done) {
        if(cs == rdsreply_error) {
            buf.data = (u_char *)p;
            buf.len = orig_p - p + orig_len;
            if(cl) {
                cl->buf->last = cl->buf->pos;
                cl = NULL;
                *ll = NULL;
            }
            u->length = 0;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
        }
        u->length = 0;
        return NGX_OK;
    }

    if(rdsreply_first_final) {}
    if(rdsreply_en_main) {}

    return NGX_OK;
}

