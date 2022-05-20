#include <ngx_http.h>
#include <libpq-fe.h>

ngx_module_t ngx_pq_module;

typedef struct {
    const char *client_encoding;
    const char **keywords;
    const char **values;
    ngx_msec_t timeout;
    PGVerbosity verbosity;
} ngx_pq_connect_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t cache_key;
#endif
    ngx_pq_connect_t connect;
} ngx_pq_loc_conf_t;

typedef struct {
    ngx_array_t caches;
} ngx_pq_main_conf_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
    ngx_pq_connect_t connect;
} ngx_pq_srv_conf_t;

static void *ngx_pq_create_main_conf(ngx_conf_t *cf) {
    ngx_pq_main_conf_t *conf;
    if (!(conf = ngx_pcalloc(cf->pool, sizeof(*conf)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
#if (NGX_HTTP_CACHE)
    if (ngx_array_init(&conf->caches, cf->pool, 1, sizeof(ngx_http_file_cache_t *)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_array_init != NGX_OK"); return NULL; }
#endif
    return conf;
}

static void *ngx_pq_create_srv_conf(ngx_conf_t *cf) {
    ngx_pq_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) return NULL;
    return conf;
}

static ngx_http_module_t ngx_pq_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = ngx_pq_create_main_conf,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pq_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = NULL,
    .merge_loc_conf = NULL
};

static ngx_command_t ngx_pq_commands[] = {
    ngx_null_command
};

ngx_module_t ngx_pq_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_pq_ctx,
    .commands = ngx_pq_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
