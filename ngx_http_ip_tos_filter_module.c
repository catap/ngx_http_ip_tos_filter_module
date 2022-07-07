
/*
 * Copyright (C) Maxim Dounin
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t         enable;
    ngx_int_t          tos;
    ngx_http_complex_value_t  tos_complex;
} ngx_http_ip_tos_conf_t;


static void *ngx_http_ip_tos_create_conf(ngx_conf_t *cf);
static char *ngx_http_ip_tos_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_ip_tos_parse_tos(ngx_str_t *value, ngx_flag_t *enable, ngx_int_t *tos);
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
    ngx_flag_t               enable;
    ngx_int_t                tos;
    ngx_http_ip_tos_conf_t  *conf;
    ngx_str_t                res;
    char *                   tos_msg;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ip_tos_filter_module);

    if (!conf->enable) {
        return ngx_http_next_header_filter(r);
    }

    tos = conf->tos;

    if (tos == -2) {
        /* variable argument */
        if (ngx_http_complex_value(r, &conf->tos_complex, &res) != NGX_OK) {
            return NGX_ERROR;
        }

        tos_msg = ngx_http_ip_tos_parse_tos(&res, &enable, &tos);
        if (tos_msg != NGX_CONF_OK) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "ip_tos: %s", tos_msg);
            return ngx_http_next_header_filter(r);
        }

        if (!enable) {
            return ngx_http_next_header_filter(r);
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ip tos: 0x%02Xi", tos);
    if(r->connection->sockaddr->sa_family == AF_INET){
      if (setsockopt(r->connection->fd, IPPROTO_IP, IP_TOS,
		     (const void *) &tos, sizeof(tos)) == -1)
	{
	  ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
			"setsockopt(IP_TOS) failed");
	}
    }else{
#ifdef IPPROTO_IPV6
      if(setsockopt(r->connection->fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) == -1)
	{
	  ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,
			"setsockopt(IPV6_TCLASS) failed");
	  
	}
#endif
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
    conf->tos = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ip_tos_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ip_tos_conf_t *prev = parent;
    ngx_http_ip_tos_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->tos, prev->tos, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_ip_tos_parse_tos(ngx_str_t *value, ngx_flag_t *enable, ngx_int_t *tos)
{
    if (ngx_strcasecmp(value->data, (u_char *) "off") == 0) {
        *enable = 0;
        return NGX_CONF_OK;
    }

    if (value->len != 4 || value->data[0] != '0' ||
        (value->data[1] != 'x' && value->data[1] != 'X'))
    {
        return "invalid argument 1";
    }

    *tos = ngx_hextoi(value->data + 2, value->len - 2);
    if (*tos == NGX_ERROR || *tos < 0 || *tos > 255) {
        return "invalid argument 2";
    }

    *enable = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_ip_tos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_tos_conf_t  *itcf = conf;

    ngx_str_t  *value;
    char       *tos_msg;
    ngx_http_compile_complex_value_t ccv;

    if (itcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &itcf->tos_complex;
    ccv.zero = 0;
    ccv.conf_prefix = 0;

    if(ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (itcf->tos_complex.lengths == NULL) {
        /* static argument */
        tos_msg = ngx_http_ip_tos_parse_tos(&value[1], &itcf->enable, &itcf->tos);
        if (tos_msg != NGX_CONF_OK) {
            return tos_msg;
        }
    } else {
        /* variable argument */
        itcf->enable = 1;
        itcf->tos = -2;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ip_tos_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ip_tos_header_filter;

    return NGX_OK;
}
