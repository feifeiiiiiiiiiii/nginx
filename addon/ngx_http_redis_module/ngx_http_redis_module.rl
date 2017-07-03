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

%%{
    machine rdsreply;

    action start_reading_size {
        ctx->chunk_bytes_read = 0;
        ctx->chunk_size = 0;
    }

    action read_chunk {
        ctx->chunks_read++;
    }

    action read_size {
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
    }

    action finalize {
        done = 1;
    }

    action test_len { ctx->chunk_bytes_read++ < ctx->chunk_size }

    action check_data_complete { ctx->chunk_bytes_read == ctx->chunk_size + 1 }

    CR = "\r";
    LF = "\n";
    CRLF = CR LF;

    chunk_size = ([1-9] digit*) >start_reading_size $read_size;

    single_line_reply = [:\+\-] (any* -- CRLF) CRLF;

    chunk_data_octet = any when test_len;

    chunk_data = chunk_data_octet+;

    chunk = "$" "0"+ CRLF
            | "$-" digit+
            | "$" chunk_size CRLF chunk_data CR when check_data_complete LF @read_chunk
            ;

    action start_reading_count {
        ctx->chunk_count = 0;
    }

    action read_count {
        ctx->chunk_count *= 10;
        ctx->chunk_count += *p - '0';
    }

    action start_reading_chunk {
        ctx->chunks_read = 0;
    }

    action test_chunk_count {
        ctx->chunks_read < ctx->chunk_count
    }

    action multi_bulk_finalize {
        if (ctx->chunk_count == ctx->chunks_read) {
            done = 1;
        }
    }

    chunk_count = ([1-9] digit*) >start_reading_count $read_count;

    reply = single_line_reply @read_chunk
          | chunk;

    protected_chunk = reply when test_chunk_count
                    ;

    multi_bulk_reply = "*" "-1" CRLF @multi_bulk_finalize
                     | "*" "0"+ CRLF @multi_bulk_finalize
                     | "*" chunk_count CRLF @start_reading_chunk
                        protected_chunk+ @multi_bulk_finalize
                     ;

    main := single_line_reply @finalize
        | chunk @finalize
        | multi_bulk_reply
        ;

}%%

%% write data;

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
        %% write init;
        ctx->state = cs;
    } else {
        cs = ctx->state;
    }

    orig_p = (signed char *)b->last;
    orig_len = bytes;

    p = (signed char *) b->last;
    pe = (signed char *) b->last + bytes;

    %% write exec;

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

