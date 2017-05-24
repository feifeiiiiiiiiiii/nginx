#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_foo_subrequest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_foo_subrequest_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_foo_subrequest_post_handler(ngx_http_request_t *r,
  void *data, ngx_int_t rc);
static void foo_subrequest_post_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_foo_subrequest_commands[] = {
  { ngx_string("mytest"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
    |NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
    ngx_http_foo_subrequest,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  ngx_null_command
};

static ngx_http_module_t ngx_http_foo_subrequest_module_ctx = {
  NULL,
  NULL,

  NULL,
  NULL,

  NULL,
  NULL,

  NULL,
  NULL
};

ngx_module_t ngx_http_foo_subrequest_module = {
  NGX_MODULE_V1,
  &ngx_http_foo_subrequest_module_ctx,
  ngx_http_foo_subrequest_commands,
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

static char *
ngx_http_foo_subrequest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_core_loc_conf_t *clcf;
  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_foo_subrequest_handler;
  return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_foo_subrequest_handler(ngx_http_request_t *r)
{
  ngx_http_post_subrequest_t *psr;
  ngx_http_request_t *sr;
  ngx_int_t rc;

  psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
  if(psr == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  psr->handler = ngx_http_foo_subrequest_post_handler;
  psr->data = NULL;
  ngx_str_t sub_prefix = ngx_string("/s");
  ngx_str_t sub_location;
  sub_location.len = sub_prefix.len + r->args.len;
  sub_location.data = ngx_palloc(r->pool, sub_location.len);
  ngx_snprintf(sub_location.data, sub_location.len,
      "%V%V", &sub_prefix, &r->args);

  rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
  if(rc != NGX_OK) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_int_t
ngx_http_foo_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
  ngx_http_request_t *pr;
  ngx_buf_t *buf;

  pr = r->parent;
  pr->headers_out.status = r->headers_out.status;

  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "Header filter add header %d", r->headers_out.status);


  if(r->headers_out.status == NGX_HTTP_OK) {
    buf = &r->upstream->buffer;

    for(; buf->pos != buf->last; buf->pos++) {
    }
  }

  pr->write_event_handler = foo_subrequest_post_handler;
  return NGX_OK;
}

static void
foo_subrequest_post_handler(ngx_http_request_t *r)
{
	if (r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_http_finalize_request(r, r->headers_out.status);
		return;
	}

  ngx_str_t str = ngx_string("hello my first subrequest");

	r->headers_out.content_length_n = str.len;

	ngx_buf_t* b = ngx_create_temp_buf(r->pool, str.len);
  b->pos = str.data;
	b->last = b->pos + str.len;
	b->last_buf = 1;

	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;

	static ngx_str_t type = ngx_string("text/plain; charset=GBK");
	r->headers_out.content_type = type;
	r->headers_out.status = NGX_HTTP_OK;

	r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
	ngx_int_t ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, &out);
  ngx_http_finalize_request(r, ret);
}
