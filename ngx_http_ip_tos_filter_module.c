
/*
 * Copyright (C) Maxim Dounin
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t         enable;
    ngx_uint_t         tos;
} ngx_http_ip_tos_conf_t;


static void *ngx_http_ip_tos_create_conf(ngx_conf_t *cf);
static char *ngx_http_ip_tos_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_ip_tos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ip_tos_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_ip_tos_commands[] = {

    { ngx_string("ip_tos"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_ip_tos,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ip_tos_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_ip_tos_init,          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_ip_tos_create_conf,   /* create location configuration */
    ngx_http_ip_tos_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_ip_tos_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_ip_tos_module_ctx,   /* module context */
    ngx_http_ip_tos_commands,      /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_ip_tos_header_filter(ngx_http_request_t *r)
{
    int                      tos;
    ngx_http_ip_tos_conf_t  *conf;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ip_tos_filter_module);

    if (!conf->enable) {
        return ngx_http_next_header_filter(r);
    }

    tos = conf->tos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ip tos: 0x%02Xi", tos);

    if (setsockopt(r->connection->fd, IPPROTO_IP, IP_TOS,
                   (const void *) &tos, sizeof(tos)) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
                      "setsockopt(IP_TOS) failed");
    }

    return ngx_http_next_header_filter(r);
}


static void *
ngx_http_ip_tos_create_conf(ngx_conf_t *cf)
{
    ngx_http_ip_tos_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_tos_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->tos = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_ip_tos_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ip_tos_conf_t *prev = parent;
    ngx_http_ip_tos_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->tos, prev->tos, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_ip_tos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_tos_conf_t  *itcf = conf;

    ngx_int_t   n;
    ngx_str_t  *value;

    if (itcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        itcf->enable = 0;
        return NGX_CONF_OK;
    }

    if (value[1].len != 4 || value[1].data[0] != '0' ||
        (value[1].data[1] != 'x' && value[1].data[1] != 'X'))
    {
        return "invalid argument 1";
    }

    n = ngx_hextoi(value[1].data + 2, value[1].len - 2);
    if (n == NGX_ERROR || n < 0 || n > 255) {
        return "invalid argument 2";
    }

    itcf->enable = 1;
    itcf->tos = n;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ip_tos_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ip_tos_header_filter;

    return NGX_OK;
}
