#include <ngx_http.h>
#include <libpq-fe.h>

#define DEF_PGPORT 5432

#ifndef WIN32
typedef int pgsocket;
#define PGINVALID_SOCKET (-1)
#else
typedef SOCKET pgsocket;
#define PGINVALID_SOCKET INVALID_SOCKET
#endif

#define PQExpBufferDataBroken(buf) ((buf).maxlen == 0)

typedef struct PQExpBufferData {
    char *data;
    size_t len;
    size_t maxlen;
} PQExpBufferData;

typedef PQExpBufferData *PQExpBuffer;

extern void appendBinaryPQExpBuffer(PQExpBuffer str, const char *data, size_t datalen);
extern void appendPQExpBufferStr(PQExpBuffer str, const char *data);
extern void initPQExpBuffer(PQExpBuffer str);
extern void resetPQExpBuffer(PQExpBuffer str);
extern void termPQExpBuffer(PQExpBuffer str);

typedef struct {
    char *message;
    ngx_log_handler_pt handler;
    void *data;
} ngx_pq_log_t;

#define ngx_pq_log_error(level, log, err, msg, fmt, ...) do { \
    ngx_pq_log_t original = { \
        .data = log->data, \
        .handler = log->handler, \
        .message = (msg), \
    }; \
    (log)->data = &original; \
    (log)->handler = ngx_pq_log_error_handler; \
    ngx_log_error(level, log, err, fmt, ##__VA_ARGS__); \
} while (0)

ngx_module_t ngx_pq_module;

enum {
    ngx_pq_type_execute = 1 << 0,
    ngx_pq_type_location = 1 << 1,
    ngx_pq_type_output = 1 << 2,
    ngx_pq_type_prepare = 1 << 3,
    ngx_pq_type_query = 1 << 4,
    ngx_pq_type_upstream = 1 << 5,
};

enum {
    ngx_pq_output_csv = 2,
    ngx_pq_output_none = 0,
    ngx_pq_output_plain = 3,
    ngx_pq_output_value = 1,
};

typedef struct {
    struct {
        ngx_int_t index;
        Oid value;
    } oid;
    struct {
        ngx_int_t index;
        ngx_str_t str;
    } value;
} ngx_pq_argument_t;

typedef struct {
    ngx_int_t index;
    ngx_str_t str;
} ngx_pq_command_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t val;
} ngx_pq_option_t;

typedef struct {
    ngx_array_t options;
    ngx_array_t queries;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
} ngx_pq_loc_conf_t;

typedef struct {
    ngx_array_t arguments;
    ngx_array_t commands;
    ngx_uint_t type;
    struct {
        ngx_int_t index;
        ngx_str_t str;
    } name;
    struct {
        ngx_flag_t header;
        ngx_flag_t string;
        ngx_int_t index;
        ngx_str_t null;
        ngx_uint_t type;
        u_char delimiter;
        u_char escape;
        u_char quote;
    } output;
} ngx_pq_query_t;

typedef struct {
    ngx_array_t options;
    ngx_array_t queries;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
} ngx_pq_srv_conf_t;

typedef struct {
    const char **paramValues;
    int nParams;
    int *paramLengths;
    ngx_pq_query_t *query;
    ngx_queue_t queue;
    Oid *paramTypes;
} ngx_pq_query_queue_t;

typedef struct {
    ngx_array_t variables;
    ngx_connection_t *connection;
    ngx_event_handler_pt read_handler;
    ngx_event_handler_pt write_handler;
    ngx_int_t rc;
    ngx_msec_t timeout;
    PGconn *conn;
    PGresult *res;
    void *data;
} ngx_pq_save_t;

typedef struct {
    ngx_http_request_t *request;
    ngx_int_t col;
    ngx_int_t row;
    ngx_peer_connection_t peer;
    ngx_pq_query_t *query;
    ngx_pq_save_t *save;
    ngx_queue_t queue;
} ngx_pq_data_t;

typedef struct {
    ngx_int_t index;
    ngx_str_t value;
} ngx_pq_variable_t;

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
    return conf;
}

static ngx_path_init_t ngx_pq_temp_path = {
    ngx_string("/var/tmp/nginx/pq_temp"), { 1, 2, 0 }
};

static char *ngx_pq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pq_loc_conf_t *prev = parent;
    ngx_pq_loc_conf_t *conf = child;
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
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_pq_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pq_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_pq_create_loc_conf,
    .merge_loc_conf = ngx_pq_merge_loc_conf
};

static u_char *ngx_pq_log_error_handler(ngx_log_t *log, u_char *buf, size_t len) {
    u_char *p = buf;
    ngx_pq_log_t *original = log->data;
    log->data = original->data;
    log->handler = original->handler;
    if (log->handler) p = log->handler(log, buf, len);
    len -= p - buf;
    buf = p;
    p = ngx_snprintf(buf, len, "\n%s", original->message);
    buf = p;
    return buf;
}

static char *PQerrorMessageMy(const PGconn *conn) {
    char *err = PQerrorMessage(conn);
    if (!err) return err;
    int len = strlen(err);
    if (!len) return err;
    if (err[len - 1] == '\n') err[len - 1] = '\0';
    return err;
}

static char *PQresultErrorMessageMy(const PGresult *res) {
    char *err = PQresultErrorMessage(res);
    if (!err) return err;
    int len = strlen(err);
    if (!len) return err;
    if (err[len - 1] == '\n') err[len - 1] = '\0';
    return err;
}

static ngx_int_t ngx_pq_output(ngx_http_request_t *r, size_t len, const u_char *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%*s", (int)len, data);
    if (!len) return NGX_OK;
    ngx_http_upstream_t *u = r->upstream;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
    *ll = cl;
    ngx_buf_t *b = cl->buf;
    if (b->start) ngx_pfree(r->pool, b->start);
    if (!(b->start = ngx_palloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NGX_ERROR; }
    b->end = b->start + len;
    b->flush = 1;
    b->last = ngx_copy(b->start, data, len);
    b->memory = 1;
    b->pos = b->start;
    b->tag = u->output.tag;
    b->temporary = 1;
    return NGX_OK;
}

static void ngx_pq_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (s) s->rc = rc;
    if (u->cleanup) (*u->cleanup)(r);
}

static ngx_int_t ngx_pq_output_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_query_t *query = d->query;
    ngx_pq_save_t *s = d->save;
    if (query->output.header) {
        if (d->row > 0) if (ngx_pq_output(r, sizeof("\n") - 1, (const u_char *)"\n") == NGX_ERROR) return NGX_ERROR;
        for (d->col = 0; d->col < PQnfields(s->res); d->col++) {
            if (d->col > 0) if (ngx_pq_output(r, sizeof(query->output.delimiter), &query->output.delimiter) == NGX_ERROR) return NGX_ERROR;
            if (query->output.string && query->output.quote) if (ngx_pq_output(r, sizeof(query->output.quote), &query->output.quote) == NGX_ERROR) return NGX_ERROR;
            const u_char *data = (const u_char *)PQfname(s->res, d->col);
            ngx_uint_t len = ngx_strlen(data);
            if (query->output.string && query->output.quote && query->output.escape) for (ngx_uint_t k = 0; k < len; k++) {
                if (data[k] == query->output.quote) if (ngx_pq_output(r, sizeof(query->output.escape), &query->output.escape) == NGX_ERROR) return NGX_ERROR;
                if (ngx_pq_output(r, sizeof(data[k]), &data[k]) == NGX_ERROR) return NGX_ERROR;
            } else {
                if (ngx_pq_output(r, len, (const u_char *)data) == NGX_ERROR) return NGX_ERROR;
            }
            if (query->output.string && query->output.quote) if (ngx_pq_output(r, sizeof(query->output.quote), &query->output.quote) == NGX_ERROR) return NGX_ERROR;
        }
    }
    for (d->row = 0; d->row < PQntuples(s->res); d->row++) {
        if (d->row > 0 || query->output.header) if (ngx_pq_output(r, sizeof("\n") - 1, (const u_char *)"\n") == NGX_ERROR) return NGX_ERROR;
        for (d->col = 0; d->col < PQnfields(s->res); d->col++) {
            if (d->col > 0) if (ngx_pq_output(r, sizeof(query->output.delimiter), &query->output.delimiter) == NGX_ERROR) return NGX_ERROR;
            if (PQgetisnull(s->res, d->row, d->col)) {
                if (query->output.null.len) if (ngx_pq_output(r, query->output.null.len, query->output.null.data) == NGX_ERROR) return NGX_ERROR;
            } else {
                if (query->output.string && query->output.quote) if (ngx_pq_output(r, sizeof(query->output.quote), &query->output.quote) == NGX_ERROR) return NGX_ERROR;
                const u_char *data = (const u_char *)PQgetvalue(s->res, d->row, d->col);
                ngx_uint_t len = PQgetlength(s->res, d->row, d->col);
                if (query->output.string && query->output.quote && query->output.escape) for (ngx_uint_t k = 0; k < len; k++) {
                    if (data[k] == query->output.quote) if (ngx_pq_output(r, sizeof(query->output.escape), &query->output.escape) == NGX_ERROR) return NGX_ERROR;
                    if (ngx_pq_output(r, sizeof(data[k]), &data[k]) == NGX_ERROR) return NGX_ERROR;
                } else {
                    if (ngx_pq_output(r, len, (const u_char *)data) == NGX_ERROR) return NGX_ERROR;
                }
                if (query->output.string && query->output.quote) if (ngx_pq_output(r, sizeof(query->output.quote), &query->output.quote) == NGX_ERROR) return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}

static void ngx_pq_result_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_http_upstream_t *u = r->upstream;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    s->rc = NGX_OK;
    if (s->res) {
        if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "ngx_queue_empty"); s->rc = NGX_ERROR; return; }
        const char *value;
        ngx_queue_t *q = ngx_queue_head(&d->queue);
        ngx_queue_remove(q);
        ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
        ngx_pq_query_t *query = d->query = qq->query;
        switch (PQresultStatus(s->res)) {
            case PGRES_TUPLES_OK: {
                if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s and %s", PQresStatus(PQresultStatus(s->res)), value); }
                else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, PQresStatus(PQresultStatus(s->res))); }
                if (s->rc == NGX_OK && query->output.type) s->rc = ngx_pq_output_handler(r);
            } break;
            default: break;
        }
        if (!(query->type & ngx_pq_type_location)) return;
        if (s->rc == NGX_OK && query->output.type && !d->row) s->rc = ngx_pq_output(r, ngx_strlen(PQcmdStatus(s->res)), (const u_char *)PQcmdStatus(s->res));
    }
    if (d && ngx_queue_empty(&d->queue)) ngx_pq_upstream_finalize_request(r, u, s->rc);
}

static ngx_int_t ngx_pq_queries_send(ngx_pq_data_t *d) {
    ngx_pq_save_t *s = d->save;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    c->read->active = 0;
    c->write->active = 0;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    if (!PQenterPipelineMode(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQenterPipelineMode"); return NGX_ERROR; }
    char *str;
    PQExpBufferData name;
    PQExpBufferData sql;
    initPQExpBuffer(&name);
    initPQExpBuffer(&sql);
    ngx_int_t rc = NGX_ERROR;
    for (ngx_queue_t *q = ngx_queue_head(&d->queue), *_; q != ngx_queue_sentinel(&d->queue) && (_ = ngx_queue_next(q)); q = _) {
        ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
        ngx_pq_query_t *query = qq->query;
        ngx_pq_command_t *command = query->commands.elts;
        resetPQExpBuffer(&sql);
        for (ngx_uint_t j = 0; j < query->commands.nelts; j++) {
            if (command[j].index) {
                if (!(str = PQescapeIdentifier(s->conn, (const char *)command[j].str.data, command[j].str.len))) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQescapeIdentifier"); goto term; }
                appendPQExpBufferStr(&sql, str);
                PQfreemem(str);
            } else appendBinaryPQExpBuffer(&sql, (const char *)command[j].str.data, command[j].str.len);
            if (PQExpBufferDataBroken(sql)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "PQExpBufferDataBroken"); goto term; }
        }
        if (query->type & ngx_pq_type_query) {
            if (!PQsendQueryParams(s->conn, sql.data, qq->nParams, qq->paramTypes, qq->paramValues, qq->paramLengths, NULL, 0)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsendQueryParams"); goto term; }
        } else {
            resetPQExpBuffer(&name);
            appendBinaryPQExpBuffer(&name, (const char *)query->name.str.data, query->name.str.len);
            if (PQExpBufferDataBroken(name)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "PQExpBufferDataBroken"); goto term; }
            if (query->type & ngx_pq_type_prepare) if (!PQsendPrepare(s->conn, name.data, sql.data, qq->nParams, qq->paramTypes)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsendPrepare"); goto term; }
            if (query->type & ngx_pq_type_execute) if (!PQsendQueryPrepared(s->conn, name.data, qq->nParams, qq->paramValues, qq->paramLengths, NULL, 0)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsendQueryPrepared"); goto term; }
        }
    }
    if (!PQpipelineSync(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQpipelineSync"); goto term; }
    s->read_handler = ngx_pq_result_handler;
    s->write_handler = ngx_pq_result_handler;
    c->read->active = 1;
    c->write->active = 0;
    rc = NGX_AGAIN;
term:
    termPQExpBuffer(&name);
    termPQExpBuffer(&sql);
    return rc;
}

static void ngx_pq_save_cln_handler(void *data) {
    ngx_pq_save_t *s = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    PQfinish(s->conn);
}

static void ngx_pq_connect_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_http_upstream_t *u = r->upstream;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    switch (PQstatus(s->conn)) {
        case CONNECTION_BAD: ngx_pq_log_error(NGX_LOG_ERR, ev->log, 0, PQerrorMessageMy(s->conn), "PQstatus == CONNECTION_BAD"); s->rc = NGX_ERROR; return;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PQstatus == CONNECTION_OK"); s->rc = ngx_pq_queries_send(d); return;
        default: break;
    }
    c = s->connection;
    s->rc = NGX_AGAIN;
    switch (PQconnectPoll(s->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_pq_log_error(NGX_LOG_ERR, ev->log, 0, PQerrorMessageMy(s->conn), "PGRES_POLLING_FAILED"); s->rc = NGX_ERROR; return;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PGRES_POLLING_OK"); s->rc = ngx_pq_queries_send(d); return;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PGRES_POLLING_READING"); c->read->active = 1; c->write->active = 0; break;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PGRES_POLLING_WRITING"); c->read->active = 0; c->write->active = 1; break;
    }
}

static ngx_int_t ngx_pq_peer_open(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    const char **keywords;
    const char **values;
    ngx_pq_data_t *d = data;
    ngx_pq_save_t *s = NULL;
    ngx_http_request_t *r = d->request;
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->upstream;
    ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
    ngx_array_t *options = pscf ? &pscf->options : &plcf->options;
    if (!(keywords = ngx_pnalloc(r->pool, (options->nelts + (pc->sockaddr->sa_family != AF_UNIX ? 1 : 0) + 2 + 1) * sizeof(*keywords)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    if (!(values = ngx_pnalloc(r->pool, (options->nelts + (pc->sockaddr->sa_family != AF_UNIX ? 1 : 0) + 2 + 1) * sizeof(*values)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    ngx_pq_option_t *option = options->elts;
    ngx_uint_t i;
    for (i = 0; i < options->nelts; i++) {
        keywords[i] = (const char *)option[i].key.data;
        values[i] = (const char *)option[i].val.data;
    }
    if (pc->sockaddr->sa_family != AF_UNIX) {
        keywords[i] = "host";
        ngx_http_upstream_t *u = r->upstream;
        ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
        ngx_http_upstream_server_t *us = uscf->servers->elts;
        ngx_str_t host = uscf->host;
        for (ngx_uint_t j = 0; j < uscf->servers->nelts; j++) if (us[j].name.data) for (ngx_uint_t k = 0; k < us[j].naddrs; k++) if (pc->sockaddr == us[j].addrs[k].sockaddr) { host = us[j].name; goto found; }
found:
        host.data[host.len] = '\0';
        for (ngx_uint_t j = 0; j < host.len; j++) if (host.data[j] == ':') { host.data[j] = '\0'; break; }
        values[i] = (const char *)host.data;
        i++;
    }
    u_char *p;
    if (!(p = ngx_pnalloc(r->pool, pc->name->len + 1))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pstrdup"); return NGX_ERROR; }
    (void)ngx_cpystrn(p, pc->name->data, pc->name->len + 1);
    keywords[i] = pc->sockaddr->sa_family != AF_UNIX ? "hostaddr" : "host";
    values[i] = (const char *)p + (pc->sockaddr->sa_family != AF_UNIX ? 0 : 5);
    i++;
    keywords[i] = "port";
    for (ngx_uint_t j = 5; j < pc->name->len; j++) if (p[j] == ':') { p[j] = '\0'; values[i] = (const char *)&p[j + 1]; break; }
    i++;
    keywords[i] = NULL;
    values[i] = NULL;
    for (i = 0; keywords[i]; i++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i: %s = %s", i, keywords[i], values[i]);
    PGconn *conn = PQconnectStartParams(keywords, values, 0);
    ngx_int_t rc = NGX_DECLINED;
    if (PQstatus(conn) == CONNECTION_BAD) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(conn), "PQstatus == CONNECTION_BAD"); goto finish; }
    if (PQsetnonblocking(conn, 1) == -1) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(conn), "PQsetnonblocking == -1"); goto finish; }
    pgsocket fd;
    if ((fd = PQsocket(conn)) == PGINVALID_SOCKET) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQsocket == PGINVALID_SOCKET"); goto finish; }
    rc = NGX_ERROR;
    ngx_connection_t *c = ngx_get_connection(fd, pc->log);
    if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_get_connection"); goto finish; }
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->read->log = pc->log;
    c->shared = 1;
    c->start_time = ngx_current_msec;
    c->type = pc->type ? pc->type : SOCK_STREAM;
    c->write->log = pc->log;
    if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); goto close; }
    if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    ngx_pool_cleanup_t *cln;
    if (!(cln = ngx_pool_cleanup_add(c->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); goto destroy; }
    cln->data = s;
    cln->handler = ngx_pq_save_cln_handler;
    s->conn = conn;
    s->connection = c;
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_conn != NGX_OK"); goto destroy; }
    } else {
        if (ngx_add_event(c->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
    }
    pc->connection = c;
    s->read_handler = ngx_pq_connect_handler;
    s->write_handler = ngx_pq_connect_handler;
    switch (PQconnectPoll(conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(conn), "PGRES_POLLING_FAILED"); goto destroy;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_OK"); return ngx_pq_queries_send(d);
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_READING"); c->read->active = 1; c->write->active = 0; break;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_WRITING"); c->read->active = 0; c->write->active = 1; break;
    }
    return NGX_AGAIN;
destroy:
    ngx_destroy_pool(c->pool);
    c->pool = NULL;
close:
    ngx_close_connection(c);
finish:
    PQfinish(conn);
    return rc;
}

static ngx_int_t ngx_pq_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pq_data_t *d = data;
    ngx_int_t rc;
    switch ((rc = d->peer.get(pc, d->peer.data))) {
        case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
        case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
        default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc); return rc;
    }
    if (!pc->connection) return ngx_pq_peer_open(pc, data);
    ngx_pq_save_t *s = NULL;
    ngx_connection_t *c = pc->connection;
    for (ngx_pool_cleanup_t *cln = c->pool->cleanup; cln; cln = cln->next) if (cln->handler == ngx_pq_save_cln_handler) { s = d->save = cln->data; break; }
    if (!s) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!s"); return NGX_ERROR; }
    return ngx_pq_queries_send(d);
}

static ngx_int_t ngx_pq_variable_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return NGX_OK;
    ngx_int_t index = data;
    ngx_pq_variable_t *variable = s->variables.elts;
    for (ngx_uint_t i = 0; i < s->variables.nelts; i++) if (variable[i].index == index) {
        v->data = variable[i].value.data;
        v->len = variable[i].value.len;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->valid = 1;
        return NGX_OK;
    }
    return NGX_OK;
}

static char *ngx_pq_argument_output_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_pq_query_t *query) {
    ngx_str_t *str = cf->args->elts;
    for (ngx_uint_t i = cmd->offset & ngx_pq_type_prepare ? 3 : 2; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("delimiter=") - 1))) return "empty \"delimiter\" value";
            if (str[i].len - (sizeof("delimiter=") - 1) > 1) return "\"delimiter\" value must be one character";
            query->output.delimiter = str[i].data[sizeof("delimiter=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("escape=") - 1))) { query->output.escape = '\0'; continue; }
            else if (str[i].len > 1) return "\"escape\" value must be one character";
            query->output.escape = str[i].data[sizeof("escape=") - 1];
            continue;
        }
        if (str[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("header=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("header=") - 1], str[i].len - (sizeof("header=") - 1))) break;
            if (!e[j].name.len) return "\"header\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            query->output.header = e[j].value;
            continue;
        }
        if (str[i].len > sizeof("output=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"output=", sizeof("output=") - 1)) {
            if (str[i].data[sizeof("output=") - 1] == '$' && cmd->offset & ngx_pq_type_upstream) {
                ngx_str_t name = str[i];
                name.data += sizeof("output=") - 1 + 1;
                name.len -= sizeof("output=") - 1 + 1;
                ngx_http_variable_t *variable;
                if (!(variable = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE))) return "!ngx_http_add_variable";
                if ((query->output.index = ngx_http_get_variable_index(cf, &name)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
                variable->get_handler = ngx_pq_variable_get_handler;
                variable->data = query->output.index;
                continue;
            }
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("csv"), ngx_pq_output_csv }, { ngx_string("plain"), ngx_pq_output_plain }, { ngx_string("value"), ngx_pq_output_value }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
            if (!e[j].name.len) return "\"output\" value must be \"csv\", \"plain\" or \"value\"";
            query->output.type = e[j].value;
            switch (query->output.type) {
                case ngx_pq_output_csv: {
                    ngx_str_set(&query->output.null, "");
                    query->output.delimiter = ',';
                    query->output.escape = '"';
                    query->output.header = 1;
                    query->output.quote = '"';
                } break;
                case ngx_pq_output_plain: {
                    ngx_str_set(&query->output.null, "\\N");
                    query->output.delimiter = '\t';
                    query->output.header = 1;
                } break;
                default: break;
            }
            continue;
        }
        if (str[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            if (!(query->output.null.len = str[i].len - (sizeof("null=") - 1))) return "empty \"null\" value";
            query->output.null.data = &str[i].data[sizeof("null=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("quote=") - 1))) { query->output.quote = '\0'; continue; }
            else if (str[i].len - (sizeof("quote=") - 1) > 1) return "\"quote\" value must be one character";
            query->output.quote = str[i].data[sizeof("quote=") - 1];
            continue;
        }
        if (str[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("string=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("string=") - 1], str[i].len - (sizeof("string=") - 1))) break;
            if (!e[j].name.len) return "\"string\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            query->output.string = e[j].value;
            continue;
        }
        ngx_pq_argument_t *argument;
        if (!query->arguments.elts && ngx_array_init(&query->arguments, cf->pool, 1, sizeof(*argument)) != NGX_OK) return "ngx_array_init != NGX_OK";
        if (!(argument = ngx_array_push(&query->arguments))) return "!ngx_array_push";
        ngx_memzero(argument, sizeof(*argument));
        ngx_str_t value = str[i];
        ngx_str_t oid = ngx_null_string;
        if (cmd->offset & ngx_pq_type_query) {
            u_char *colon;
            if ((colon = ngx_strstrn(value.data, "::", sizeof("::") - 1 - 1))) {
                value.len = colon - value.data;
                oid.data = colon + sizeof("::") - 1;
                oid.len = str[i].len - value.len - sizeof("::") + 1;
            }
        } else if (cmd->offset & ngx_pq_type_prepare) oid = value;
        if (!(cmd->offset & ngx_pq_type_prepare)) {
            if (value.data[0] == '$') {
                value.data++;
                value.len--;
                if ((argument->value.index = ngx_http_get_variable_index(cf, &value)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
            } else argument->value.str = value;
        }
        if (!oid.len) continue;
        if (oid.data[0] == '$') {
            oid.data++;
            oid.len--;
            if ((argument->oid.index = ngx_http_get_variable_index(cf, &oid)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
        } else {
            ngx_int_t n = ngx_atoi(oid.data, oid.len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            argument->oid.value = n;
        }
    }
    return NGX_CONF_OK;
}

static char *ngx_pq_execute_loc_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t *queries) {
    ngx_pq_query_t *query;
    if (!queries->elts && ngx_array_init(queries, cf->pool, 1, sizeof(*query)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(query = ngx_array_push(queries))) return "!ngx_array_push";
    ngx_memzero(query, sizeof(*query));
    ngx_str_t *str = cf->args->elts;
    if (str[1].data[0] == '$') {
        str[1].data++;
        str[1].len--;
        if ((query->name.index = ngx_http_get_variable_index(cf, &str[1])) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    } else query->name.str = str[1];
    query->type = cmd->offset;
    return ngx_pq_argument_output_loc_conf(cf, cmd, query);
}

static char *ngx_pq_execute_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    return ngx_pq_execute_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pq_execute_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    return ngx_pq_execute_loc_ups_conf(cf, cmd, &pscf->queries);
}

static char *ngx_pq_log_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    return ngx_log_set_log(cf, &pscf->log);
}

static void ngx_pq_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_pq_save_t *s = c->data;
//    if (!ngx_terminate && !ngx_exiting && !c->error && !ev->error && !ev->timedout && ngx_pq_process(s) == NGX_OK) { ngx_add_timer(c->read, s->timeout); return; }
    c->data = s->data;
    s->read_handler(ev);
}

static void ngx_pq_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
}

static void ngx_pq_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %ui", state);
    ngx_pq_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_pq_save_t *s = d->save;
    d->save = NULL;
    if (!s) return;
    if (!ngx_queue_empty(&d->queue)) {
        PGcancel *cancel = PQgetCancel(s->conn);
        if (!cancel) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(s->conn), "!PQgetCancel"); return; }
        char errbuf[256];
        if (!PQcancel(cancel, errbuf, sizeof(errbuf))) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, errbuf, "!PQcancel"); PQfreeCancel(cancel); return; }
        PQfreeCancel(cancel);
    }
    if (pc->connection) return;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->upstream;
    ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
    if (!pscf) return;
    ngx_connection_t *c = s->connection;
    if (c->read->timer_set) s->timeout = c->read->timer.key - ngx_current_msec;
    s->data = c->data;
    s->read_handler = c->read->handler;
    s->write_handler = c->write->handler;
    c->data = s;
    c->read->handler = ngx_pq_read_handler;
    c->write->handler = ngx_pq_write_handler;
    if (!pscf->log) return;
    c->log = pscf->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;
}

static ngx_int_t ngx_pq_queries_init(ngx_http_request_t *r, ngx_array_t *queries) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_query_t *query = queries->elts;
    for (ngx_uint_t i = 0; i < queries->nelts; i++) {
        ngx_pq_query_queue_t *qq;
        if (!(qq = ngx_pcalloc(r->pool, sizeof(*qq)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        ngx_queue_insert_tail(&d->queue, &qq->queue);
        qq->query = &query[i];
        qq->nParams = query[i].arguments.nelts;
        ngx_pq_argument_t *argument = query[i].arguments.elts;
        if (!(qq->paramLengths = ngx_pnalloc(r->pool, qq->nParams * sizeof(*qq->paramLengths)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (!(qq->paramTypes = ngx_pnalloc(r->pool, qq->nParams * sizeof(*qq->paramTypes)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (!(qq->paramValues = ngx_pnalloc(r->pool, qq->nParams * sizeof(*qq->paramValues)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_int_t j = 0; j < qq->nParams; j++) {
            if (argument[j].oid.index && (query[i].type & ngx_pq_type_query || query[i].type & ngx_pq_type_prepare)) {
                ngx_http_variable_value_t *value;
                if (!(value = ngx_http_get_indexed_variable(r, argument[j].oid.index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
                ngx_int_t n = ngx_atoi(value->data, value->len);
                if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
                argument[j].oid.value = n;
            }
            qq->paramTypes[j] = argument[j].oid.value;
            if (argument[j].value.index && (query[i].type & ngx_pq_type_query || query[i].type & ngx_pq_type_execute)) {
                ngx_http_variable_value_t *value;
                if (!(value = ngx_http_get_indexed_variable(r, argument[j].value.index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
                argument[j].value.str.data = value->data;
                argument[j].value.str.len = value->len;
            }
            qq->paramLengths[j] = argument[j].value.str.len;
            qq->paramValues[j] = (const char *)argument[j].value.str.data;
        }
        ngx_pq_command_t *command = query[i].commands.elts;
        for (ngx_uint_t j = 0; j < query[i].commands.nelts; j++) if (command[j].index) {
            ngx_http_variable_value_t *value;
            if (!(value = ngx_http_get_indexed_variable(r, command[j].index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
            command[j].str.data = value->data;
            command[j].str.len = value->len;
        }
        if (!(query[i].type & ngx_pq_type_query) && query[i].name.index) {
            ngx_http_variable_value_t *value;
            if (!(value = ngx_http_get_indexed_variable(r, query[i].name.index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NGX_ERROR; }
            query[i].name.str.data = value->data;
            query[i].name.str.len = value->len;
        }
    }
    return NGX_OK;
}

static ngx_int_t ngx_pq_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    ngx_array_t *queries = &plcf->queries;
    ngx_pq_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_queue_init(&d->queue);
    if (uscf->srv_conf) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
        if (pscf->queries.nelts) queries = &pscf->queries;
        if (pscf->peer.init(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
    } else {
        if (ngx_http_upstream_init_round_robin_peer(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_init_round_robin_peer != NGX_OK"); return NGX_ERROR; }
    }
    ngx_http_upstream_t *u = r->upstream;
    d->peer = u->peer;
    d->request = r;
    u->conf->upstream = uscf;
    u->peer.data = d;
    u->peer.free = ngx_pq_peer_free;
    u->peer.get = ngx_pq_peer_get;
    return ngx_pq_queries_init(r, queries);
}

static ngx_int_t ngx_pq_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    if (uscf->srv_conf) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
        if (pscf->peer.init_upstream(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "peer.init_upstream != NGX_OK"); return NGX_ERROR; }
        pscf->peer.init = uscf->peer.init ? uscf->peer.init : ngx_http_upstream_init_round_robin_peer;
    } else {
        if (ngx_http_upstream_init_round_robin(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_http_upstream_init_round_robin != NGX_OK"); return NGX_ERROR; }
    }
    uscf->peer.init = ngx_pq_peer_init;
    return NGX_OK;
}

static void ngx_pq_abort_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}

static ngx_int_t ngx_pq_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    if (uscf->peer.init != ngx_pq_peer_init) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "uscf->peer.init != ngx_pq_peer_init");
    uscf->peer.init = ngx_pq_peer_init;
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    if (plcf->complex.value.data) {
        ngx_str_t host;
        if (ngx_http_complex_value(r, &plcf->complex, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        if (!host.len) { ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"pq_pass\" (was: \"%V\") in location \"%V\"", &plcf->complex.value, &clcf->name); return NGX_ERROR; }
        if (!(u->resolved = ngx_pcalloc(r->pool, sizeof(*u->resolved)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        u->resolved->host = host;
        u->resolved->no_port = 1;
    }
    u->headers_in.status_n = NGX_HTTP_OK;
    if (!plcf->queries.nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!queries"); return NGX_ERROR; }
    u->request_sent = 1; // force to reinit_request
    return NGX_OK;
}

static ngx_int_t ngx_pq_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return NGX_OK;
}

static void ngx_pq_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    ngx_http_upstream_t *u = r->upstream;
    u->keepalive = !u->headers_in.connection_close;
    u->request_body_sent = 1;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
    switch (s->rc) {
        case NGX_ERROR: s->rc = ngx_http_filter_finalize_request(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR); return;
    }
    if (!r->headers_out.status) r->headers_out.status = NGX_HTTP_OK;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return;
    u->header_sent = 1;
    ngx_chain_t *cl;
    if (!(cl = u->out_bufs)) return;
    while (cl->next) cl = cl->next;
    ngx_buf_t *b = cl->buf;
    if (r == r->main && !r->post_action) b->last_buf = 1; else {
        b->sync = 1;
        b->last_in_chain = 1;
    }
    if (ngx_http_output_filter(r, u->out_bufs) != NGX_OK) return;
    ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs, &u->out_bufs, u->output.tag);
}

static void ngx_pq_read_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    ngx_connection_t *c = s->connection;
    if (PQstatus(s->conn) == CONNECTION_OK && !PQconsumeInput(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, r->connection->log, 0, PQerrorMessageMy(s->conn), "!PQconsumeInput"); ngx_pq_upstream_finalize_request(r, u, NGX_ERROR); return; }
    s->rc = NGX_OK;
    const char *value;
    while (PQstatus(s->conn) == CONNECTION_OK) {
        if (!(s->res = PQgetResult(s->conn))) continue;
        if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(s->res)), value); }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, PQresStatus(PQresultStatus(s->res))); }
        switch (PQresultStatus(s->res)) {
            case PGRES_FATAL_ERROR: {
                if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_pq_log_error(NGX_LOG_ERR, r->connection->log, 0, PQresultErrorMessageMy(s->res), "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), value); }
                else { ngx_pq_log_error(NGX_LOG_ERR, r->connection->log, 0, PQresultErrorMessageMy(s->res), "PQresultStatus == %s", PQresStatus(PQresultStatus(s->res))); }
                ngx_pq_upstream_finalize_request(r, u, NGX_ERROR); return;
            } break;
            case PGRES_PIPELINE_SYNC: goto done;
            default: break;
        }
        if (s->rc == NGX_OK) s->read_handler(c->read);
        PQclear(s->res);
    }
done:
    if ((s->res = PQgetResult(s->conn))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQgetResult"); ngx_pq_upstream_finalize_request(r, u, NGX_ERROR); return; }
    if (!PQexitPipelineMode(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, r->connection->log, 0, PQerrorMessageMy(s->conn), "!PQexitPipelineMode"); ngx_pq_upstream_finalize_request(r, u, NGX_ERROR); return; }
    s->res = NULL;
    if (s->rc == NGX_OK) s->read_handler(c->read);
    switch (s->rc) {
        case NGX_ERROR: ngx_pq_upstream_finalize_request(r, u, NGX_ERROR); return;
    }
}

static void ngx_pq_write_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    ngx_connection_t *c = s->connection;
    s->rc = NGX_OK;
    if (s->rc == NGX_OK) s->write_handler(c->write);
    switch (s->rc) {
        case NGX_ERROR: ngx_pq_upstream_finalize_request(r, u, NGX_ERROR); return;
    }
}

static ngx_int_t ngx_pq_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    r->state = 0;
    u->read_event_handler = ngx_pq_read_event_handler;
    u->write_event_handler = ngx_pq_write_event_handler;
    return NGX_OK;
}

static ngx_int_t ngx_pq_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_int_t rc;
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    if (plcf->upstream.pass_request_body && (rc = ngx_http_discard_request_body(r)) != NGX_OK) return rc;
    if (ngx_http_set_content_type(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_set_content_type != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    ngx_str_set(&u->schema, "pq://");
    u->output.tag = (ngx_buf_tag_t)&ngx_pq_module;
    u->conf = &plcf->upstream;
    r->state = 0;
    u->abort_request = ngx_pq_abort_request;
    u->create_request = ngx_pq_create_request;
    u->finalize_request = ngx_pq_finalize_request;
    u->process_header = ngx_pq_process_header;
    u->reinit_request = ngx_pq_reinit_request;
    u->buffering = u->conf->buffering;
    if (!u->conf->request_buffering && u->conf->pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
    if ((rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init)) >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
    return NGX_DONE;
}

static char *ngx_pq_option_loc_ups_conf(ngx_conf_t *cf, ngx_array_t *options) {
    if (options->elts) return "is duplicate";
    ngx_pq_option_t *option;
    if (ngx_array_init(options, cf->pool, cf->args->nelts - 1, sizeof(*option)) != NGX_OK) return "ngx_array_init != NGX_OK";
    ngx_str_t *str = cf->args->elts;
    ngx_flag_t application_name = 0;
    u_char *p;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("host=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"host=", sizeof("host=") - 1)) return "\"host\" option not allowed!";
        else if (str[i].len > sizeof("hostaddr=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"hostaddr=", sizeof("hostaddr=") - 1)) return "\"hostaddr\" option not allowed!";
        else if (str[i].len > sizeof("port=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"port=", sizeof("port=") - 1)) return "\"port\" option not allowed!";
        else if (str[i].len > sizeof("application_name=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"application_name=", sizeof("application_name=") - 1)) application_name = 1;
        else if (str[i].len > sizeof("fallback_application_name=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"fallback_application_name=", sizeof("fallback_application_name=") - 1)) application_name = 1;
        if (!(option = ngx_array_push(options))) return "!ngx_array_push";
        ngx_memzero(option, sizeof(*option));
        if (!(p = ngx_strlchr(str[i].data, str[i].data + str[i].len, '='))) return "!ngx_strlchr";
        option->key.data = str[i].data;
        option->key.len = p - str[i].data;
        option->key.data[option->key.len] = '\0';
        option->val.data = str[i].data + option->key.len + 1;
        option->val.len = str[i].len - option->key.len - 1;
    }
    if (!application_name) {
        if (!(option = ngx_array_push(options))) return "!ngx_array_push";
        ngx_memzero(option, sizeof(*option));
        ngx_str_set(&option->key, "application_name");
        ngx_str_set(&option->val, "nginx");
    }
    return NGX_CONF_OK;
}

static char *ngx_pq_option_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    return ngx_pq_option_loc_ups_conf(cf, &plcf->options);
}

static char *ngx_pq_option_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (uscf->peer.init_upstream != ngx_pq_peer_init_upstream) {
        pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
        uscf->peer.init_upstream = ngx_pq_peer_init_upstream;
    }
    return ngx_pq_option_loc_ups_conf(cf, &pscf->options);
}

static char *ngx_pq_pass_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream || plcf->complex.value.data) return "is duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pq_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_str_t *str = cf->args->elts;
    if (ngx_http_script_variables_count(&str[1])) {
        ngx_http_compile_complex_value_t ccv = {cf, &str[1], &plcf->complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        return NGX_CONF_OK;
    }
    ngx_url_t url = {0};
    if (!plcf->options.elts) url.no_resolve = 1;
    url.url = str[1];
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) return NGX_CONF_ERROR;
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pq_peer_init_upstream;
    return NGX_CONF_OK;
}

static char *ngx_pq_prepare_query_loc_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t *queries) {
    ngx_pq_query_t *query;
    if (!queries->elts && ngx_array_init(queries, cf->pool, 1, sizeof(*query)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(query = ngx_array_push(queries))) return "!ngx_array_push";
    ngx_memzero(query, sizeof(*query));
    ngx_pq_command_t *command;
    if (ngx_array_init(&query->commands, cf->pool, 1, sizeof(*command)) != NGX_OK) return "ngx_array_init != NGX_OK";
    ngx_str_t *str = cf->args->elts;
    ngx_uint_t i = 1;
    query->type = cmd->offset;
    if (cmd->offset & ngx_pq_type_prepare) {
        if (str[i].data[0] == '$') {
            str[i].data++;
            str[i].len--;
            if ((query->name.index = ngx_http_get_variable_index(cf, &str[i])) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
        } else query->name.str = str[i];
        i++;
    }
    u_char *b = str[i].data;
    u_char *e = str[i].data + str[i].len;
    u_char *n = b;
    u_char *s = n;
    while (s < e) {
        if (*s++ == '$') {
            if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || *s == '_') {
                if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
                ngx_memzero(command, sizeof(*command));
                command->str.data = n;
                command->str.len = s - n - 1;
                n = s;
                while (s < e && ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || *s == '_')) s++;
                if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
                ngx_memzero(command, sizeof(*command));
                command->str.data = n;
                command->str.len = s - n;
                n = s;
                if (*s != '$') if ((command->index = ngx_http_get_variable_index(cf, &command->str)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
            } else {
                if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
                ngx_memzero(command, sizeof(*command));
                command->str.data = n;
                command->str.len = s - n;
                n = s;
            }
        }
    }
    if (n < s) {
        if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
        ngx_memzero(command, sizeof(*command));
        command->str.data = n;
        command->str.len = s - n;
    }
    return ngx_pq_argument_output_loc_conf(cf, cmd, query);
}

static char *ngx_pq_prepare_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    return ngx_pq_prepare_query_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pq_prepare_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    return ngx_pq_prepare_query_loc_ups_conf(cf, cmd, &pscf->queries);
}

static char *ngx_pq_query_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    return ngx_pq_prepare_query_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pq_query_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    return ngx_pq_prepare_query_loc_ups_conf(cf, cmd, &pscf->queries);
}

static ngx_conf_bitmask_t ngx_pq_next_upstream_masks[] = {
  { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
  { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
  { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
  { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
  { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
  { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
  { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
  { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
  { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
  { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
  { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
  { ngx_null_string, 0 }
};

static ngx_command_t ngx_pq_commands[] = {
  { ngx_string("pq_execute"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_execute_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_execute|ngx_pq_type_output, NULL },
  { ngx_string("pq_execute"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_execute_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_execute, NULL },
  { ngx_string("pq_log"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_log_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_option"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_option_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_option"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_option_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_pass"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1, ngx_pq_pass_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_prepare"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_prepare_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_prepare, NULL },
  { ngx_string("pq_prepare"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_prepare_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_prepare, NULL },
  { ngx_string("pq_query"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_query_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_query|ngx_pq_type_output, NULL },
  { ngx_string("pq_query"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_query_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_query, NULL },
  { ngx_string("pq_buffering"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.buffering), NULL },
  { ngx_string("pq_buffer_size"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.buffer_size), NULL },
  { ngx_string("pq_buffers"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2, ngx_conf_set_bufs_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.bufs), NULL },
  { ngx_string("pq_busy_buffers_size"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.busy_buffers_size_conf), NULL },
  { ngx_string("pq_connect_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.connect_timeout), NULL },
  { ngx_string("pq_ignore_client_abort"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.ignore_client_abort), NULL },
  { ngx_string("pq_intercept_errors"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.intercept_errors), NULL },
  { ngx_string("pq_next_upstream"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.next_upstream), &ngx_pq_next_upstream_masks },
  { ngx_string("pq_next_upstream_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.next_upstream_timeout), NULL },
  { ngx_string("pq_next_upstream_tries"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.next_upstream_tries), NULL },
  { ngx_string("pq_pass_request_body"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.pass_request_body), NULL },
  { ngx_string("pq_read_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.read_timeout), NULL },
  { ngx_string("pq_request_buffering"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.request_buffering), NULL },
  { ngx_string("pq_send_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.send_timeout), NULL },
  { ngx_string("pq_socket_keepalive"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.socket_keepalive), NULL },
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
