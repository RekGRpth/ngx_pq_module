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

static void *ngx_pq_create_loc_conf(ngx_conf_t *cf) {
    ngx_pq_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) return NULL;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.preserve_output = 1;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    ngx_str_set(&conf->upstream.module, "pq");
#if (NGX_HTTP_CACHE)
    conf->upstream.cache_background_update = NGX_CONF_UNSET;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache = NGX_CONF_UNSET;
    conf->upstream.cache_revalidate = NGX_CONF_UNSET;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
#endif
    return conf;
}

static ngx_path_init_t ngx_pq_temp_path = {
    ngx_string("/var/tmp/nginx/pq_temp"), { 1, 2, 0 }
};

static char *ngx_pq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pq_loc_conf_t *prev = parent;
    ngx_pq_loc_conf_t *conf = child;
#if (NGX_HTTP_CACHE)
    if (conf->upstream.store > 0) conf->upstream.cache = 0;
    if (conf->upstream.cache > 0) conf->upstream.store = 0;
#endif
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs, 8, ngx_pagesize);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t)ngx_pagesize);
    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf, prev->upstream.busy_buffers_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 1);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body, prev->upstream.pass_request_body, 0);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.bufs.num < 2) return "there must be at least 2 \"pq_buffers\"";
    size_t size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) size = conf->upstream.bufs.size;
    conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.busy_buffers_size_conf;
    if (conf->upstream.busy_buffers_size < size) return "\"pq_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"pq_buffer_size\" and one of the \"pq_buffers\"";
    if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) return "\"pq_busy_buffers_size\" must be less than the size of all \"pq_buffers\" minus one buffer";
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path, prev->upstream.temp_path, &ngx_pq_temp_path) != NGX_OK) return NGX_CONF_ERROR;
#if (NGX_HTTP_CACHE)
    if (conf->upstream.cache == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.cache, prev->upstream.cache, 0);
        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }
    if (conf->upstream.cache_zone && !conf->upstream.cache_zone->data) { ngx_shm_zone_t *shm_zone = conf->upstream.cache_zone; ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"pq_cache\" zone \"%V\" is unknown", &shm_zone->shm.name); return NGX_CONF_ERROR; }
    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses, prev->upstream.cache_min_uses, 1);
    ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset, prev->upstream.cache_max_range_offset, NGX_MAX_OFF_T_VALUE);
    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale, prev->upstream.cache_use_stale, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF);
    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    if (!conf->upstream.cache_methods) conf->upstream.cache_methods = prev->upstream.cache_methods;
    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;
    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass, prev->upstream.cache_bypass, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.no_cache, prev->upstream.no_cache, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.cache_valid, prev->upstream.cache_valid, NULL);
    if (!conf->cache_key.value.data) conf->cache_key = prev->cache_key;
    if (conf->upstream.cache && !conf->cache_key.value.data) return "no \"pq_cache_key\" for \"pq_cache\"";
    ngx_conf_merge_value(conf->upstream.cache_lock, prev->upstream.cache_lock, 0);
    ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout, prev->upstream.cache_lock_timeout, 5000);
    ngx_conf_merge_msec_value(conf->upstream.cache_lock_age, prev->upstream.cache_lock_age, 5000);
    ngx_conf_merge_value(conf->upstream.cache_revalidate, prev->upstream.cache_revalidate, 0);
    ngx_conf_merge_value(conf->upstream.cache_background_update, prev->upstream.cache_background_update, 0);
#endif
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_pq_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = ngx_pq_create_main_conf,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pq_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_pq_create_loc_conf,
    .merge_loc_conf = ngx_pq_merge_loc_conf
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
