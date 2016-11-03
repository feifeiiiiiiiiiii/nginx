
/*
 * Author feifeiiiiiiiii
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_array_t *allow_methods;
    ngx_array_t *deny_methods;
} ngx_http_method_access_loc_conf_t;

static ngx_str_t http_methods[] = {
    ngx_string("GET"),
    ngx_string("PUT"),
    ngx_string("PATCH"),
    ngx_string("POST"),
    ngx_string("DELETE"),
    ngx_string(NULL)
};

static ngx_int_t ngx_http_method_access_handler(ngx_http_request_t *r);
static void *ngx_http_method_access_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_method_access_init(ngx_conf_t *cf);
static char *ngx_http_method_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_method_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_method_access_commands[] = {

    { ngx_string("method_allow"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_method_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_method_access_loc_conf_t, allow_methods),
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_method_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_method_access_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_method_access_create_loc_conf,       /* create location configuration */
    ngx_http_method_access_merge_loc_conf         /* merge location configuration */
};

ngx_module_t  ngx_http_method_access_module = {
    NGX_MODULE_V1,
    &ngx_http_method_access_module_ctx,           /* module context */
    ngx_http_method_access_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_method_access_handler(ngx_http_request_t *r)
{
    ngx_http_method_access_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_method_access_module);

    ngx_str_t method_name = r->method_name;
    ngx_uint_t method_allows_len = alcf->allow_methods->nelts;
    ngx_str_t *value;
    value = alcf->allow_methods->elts;

    ngx_uint_t i = 0;
    while (i < method_allows_len) {
        if (ngx_strncmp(value[i].data, method_name.data, method_name.len) == 0) {
            return NGX_DECLINED;
        }
        i++;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "method not allowed %V", &method_name);
    return NGX_HTTP_FORBIDDEN;
}

static void *
ngx_http_method_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_method_access_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_method_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static char *
ngx_http_method_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_method_access_loc_conf_t  *prev = parent;
    ngx_http_method_access_loc_conf_t  *conf = child;

    if (conf->allow_methods == NULL) {
        conf->allow_methods = prev->allow_methods;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_method_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_method_access_handler;

    return NGX_OK;
}

static char *
ngx_http_method_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_method_access_loc_conf_t *alcf = conf;

    if (alcf->allow_methods == NULL) {
        alcf->allow_methods = ngx_array_create(cf->pool, 5, sizeof(ngx_str_t));
        if (alcf->allow_methods == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_str_t *rule;
    ngx_str_t *value;
    value = cf->args->elts;

    ngx_uint_t i, j;
    for (i = 1; i < cf->args->nelts; ++i) {
        j = 0;
        ngx_flag_t exist = false;
        while(http_methods[j].data != NULL) {
            if (ngx_strcmp(value[i].data, http_methods[j].data) == 0) {
                exist = true;
                break;
            }
            j++;
        }
        if (!exist) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "Methods not support \"%V\", support methods: GET,PUT,POST,DELETE,PATCH", &value[i]);
            return NGX_CONF_ERROR;
        }
        rule = ngx_array_push(alcf->allow_methods);
        rule->len = value[i].len;
        rule->data = value[i].data;
    }
    return NGX_OK;
}
