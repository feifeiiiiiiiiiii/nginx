#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_echo_handler(ngx_http_request_t *r);
static char *ngx_http_echo_loc_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_echo_create_loc_conf(ngx_conf_t *cf);

typedef struct {
    ngx_str_t echostr;
} ngx_http_echo_loc_conf_t;

static ngx_command_t  ngx_http_echo_commands[] = {
    { ngx_string("echo"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_echo_loc_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_echo_loc_conf_t, echostr),
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_echo_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    ngx_http_echo_create_loc_conf,  /* create location configuration */
    NULL /* merge location configuration */
};

ngx_module_t  ngx_http_echo_module = {
    NGX_MODULE_V1,
    &ngx_http_echo_module_ctx, /* module context */
    ngx_http_echo_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,   /* init master */
    NULL,   /* init module */
    NULL,                          /* init process */
    NULL,   /* init thread */
    NULL,   /* exit thread */
    NULL,                          /* exit process */
    NULL,   /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_echo_loc_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_echo_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_echo_handler(ngx_http_request_t *r)
{
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t response = ngx_string("echo hello");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b;
    b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;

    ngx_chain_t   out;
    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_echo_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_echo_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_echo_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

