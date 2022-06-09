#include <ngx_http.h>
#include "ngx_http_upstream.c"

#undef OPENSSL_API_COMPAT

#include <internal/c.h>
#include <internal/libpq-int.h>
#include <internal/pqexpbuffer.h>
#include <libpq-fe.h>

extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));

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
        ngx_http_complex_value_t complex;
        Oid value;
    } oid;
    struct {
        ngx_http_complex_value_t complex;
        ngx_str_t str;
    } value;
} ngx_pq_argument_t;

typedef struct {
    ngx_int_t index;
    ngx_str_t str;
} ngx_pq_command_t;

typedef struct {
    ngx_array_t options;
    ngx_msec_t timeout;
    PGContextVisibility show_context;
    PGVerbosity errors;
} ngx_pq_connect_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
    ngx_pq_connect_t connect;
} ngx_pq_loc_conf_t;

typedef struct {
    ngx_array_t arguments;
    ngx_array_t commands;
    ngx_flag_t header;
    ngx_flag_t string;
    ngx_int_t index;
    ngx_str_t null;
    ngx_uint_t output;
    ngx_uint_t type;
    u_char delimiter;
    u_char escape;
    u_char quote;
    struct {
        ngx_http_complex_value_t complex;
        ngx_str_t str;
    } name;
} ngx_pq_query_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
    ngx_pq_connect_t connect;
    size_t buffer_size;
} ngx_pq_srv_conf_t;

typedef struct {
    const char **paramValues;
    ngx_pq_query_t *query;
    ngx_queue_t queue;
    Oid *paramTypes;
} ngx_pq_query_queue_t;

typedef struct {
    ngx_queue_t queue;
    ngx_str_t channel;
} ngx_pq_channel_queue_t;

typedef struct {
    ngx_str_t column_name;
    ngx_str_t constraint_name;
    ngx_str_t context;
    ngx_str_t datatype_name;
    ngx_str_t internal_position;
    ngx_str_t internal_query;
    ngx_str_t message_detail;
    ngx_str_t message_hint;
    ngx_str_t message_primary;
    ngx_str_t schema_name;
    ngx_str_t severity;
    ngx_str_t severity_nonlocalized;
    ngx_str_t source_file;
    ngx_str_t source_function;
    ngx_str_t source_line;
    ngx_str_t sqlstate;
    ngx_str_t statement_position;
    ngx_str_t table_name;
} ngx_pq_error_t;

typedef struct {
    int inBufSize;
    ngx_array_t variables;
    ngx_connection_t *connection;
    ngx_event_handler_pt read;
    ngx_event_handler_pt write;
    ngx_msec_t timeout;
    ngx_queue_t queue;
    ngx_uint_t count;
    PGconn *conn;
} ngx_pq_save_t;

typedef struct {
    ngx_array_t variables;
    ngx_http_request_t *request;
    ngx_int_t row;
    ngx_peer_connection_t peer;
    ngx_pq_error_t error;
    ngx_pq_save_t *save;
    ngx_queue_t queue;
    ngx_uint_t type;
} ngx_pq_data_t;

typedef struct {
    ngx_chain_t *cl;
    ngx_int_t index;
} ngx_pq_variable_t;

static u_char *ngx_pq_log_error_handler(ngx_log_t *log, u_char *buf, size_t len) {
    u_char *p = buf;
    ngx_pq_log_t *original = log->data;
    log->data = original->data;
    log->handler = original->handler;
    if (log->handler) p = log->handler(log, buf, len);
    len -= p - buf;
    buf = p;
    if (original->message) {
        int msg_len = strlen(original->message);
        if (msg_len) {
            if (original->message[msg_len - 1] == '\n') original->message[msg_len - 1] = '\0';
            p = ngx_snprintf(buf, len, "\n%s", original->message);
            buf = p;
        }
    }
    return buf;
}

static ngx_int_t ngx_pq_output(ngx_pq_save_t *s, ngx_pq_data_t *d, ngx_pq_query_t *query, const u_char *data, size_t len) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    if (!len) return NGX_OK;
    if (!d) return NGX_OK;
    ngx_http_request_t *r = d->request;
    if (query->index) {
        ngx_array_t *variables;
        ngx_connection_t *c;
        if (query->type & ngx_pq_type_upstream) {
            c = s->connection;
            variables = &s->variables;
        } else if (query->type & ngx_pq_type_location) {
            c = r->connection;
            variables = &d->variables;
        } else return NGX_OK;
        ngx_pq_variable_t *variable = variables->elts;
        ngx_uint_t i;
        for (i = 0; i < variables->nelts; i++) if (variable[i].index == query->index) break;
        ngx_chain_t *cl;
        if (i == variables->nelts) {
            if (!variables->elts && ngx_array_init(&s->variables, c->pool, 1, sizeof(*variable)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
            if (!(variable = ngx_array_push(&s->variables))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
            ngx_memzero(variable, sizeof(*variable));
            variable->index = query->index;
            if (!(cl = variable->cl = ngx_alloc_chain_link(c->pool))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        } else {
            variable = &variable[i];
            cl = variable->cl;
            if (!(cl = cl->next = ngx_alloc_chain_link(c->pool))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
        cl->next = NULL;
        if (!(cl->buf = ngx_create_temp_buf(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
        cl->buf->last = ngx_copy(cl->buf->last, data, len);
    } else if (query->output) {
        ngx_http_upstream_t *u = r->upstream;
        ngx_chain_t *cl, **ll;
        for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
        if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
        *ll = cl;
        ngx_buf_t *b = cl->buf;
        if (b->start) ngx_pfree(r->pool, b->start);
        if (!(b->start = ngx_palloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_palloc"); return NGX_ERROR; }
        b->end = b->start + len;
        b->flush = 1;
        b->last = ngx_copy(b->start, data, len);
        b->memory = 1;
        b->pos = b->start;
        b->tag = u->output.tag;
        b->temporary = 1;
    }
    return NGX_OK;
}

static ngx_int_t ngx_pq_copy_error(ngx_pq_data_t *d, PGresult *res, int fieldcode, ngx_uint_t offset) {
    ngx_http_request_t *r = d->request;
    char *err;
    if (!(err = PQresultErrorField(res, fieldcode))) return NGX_OK;
    ngx_str_t str = {ngx_strlen(err), (u_char *)err};
    ngx_str_t *error = (ngx_str_t *)((u_char *)&d->error + offset);
    if (!(error->data = ngx_pstrdup(r->pool, &str))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; }
    error->len = str.len;
    return NGX_OK;
}

static ngx_int_t ngx_pq_res_command_ok(ngx_pq_save_t *s, ngx_pq_data_t *d, PGresult *res) {
    char *value;
    size_t len = 0;
    if ((value = PQcmdStatus(res)) && (len = ngx_strlen(value))) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(res)), value); }
    else { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", PQresStatus(PQresultStatus(res))); }
    if (s->count) { s->count--; return NGX_OK; }
    if (!d) return NGX_OK;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
    ngx_pq_query_t *query = qq->query;
    d->type = query->type;
    if (ngx_http_push_stream_delete_channel_my && query->commands.nelts == 2 && len == sizeof("LISTEN") - 1 && !ngx_strncasecmp((u_char *)value, (u_char *)"LISTEN", sizeof("LISTEN") - 1)) {
        ngx_pq_command_t *command = query->commands.elts;
        command = &command[1];
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V", &command->str);
        ngx_pq_channel_queue_t *cq;
        ngx_connection_t *c = s->connection;
        if (!(cq = ngx_pcalloc(c->pool, sizeof(*cq)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        ngx_queue_insert_tail(&s->queue, &cq->queue);
        if (!(cq->channel.data = ngx_pstrdup(c->pool, &command->str))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pstrdup"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        cq->channel.len = command->str.len;
    }
    return NGX_OK;
}
static ngx_int_t ngx_pq_res_copy_out(ngx_pq_save_t *s, ngx_pq_data_t *d) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_COPY_OUT");
    char *buffer = NULL;
    int len;
    ngx_int_t rc = NGX_OK;
    switch ((len = PQgetCopyData(s->conn, &buffer, 0))) {
        case 0: break;
        case -1: break;
        case -2: ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "PQgetCopyData == -2"); rc = NGX_HTTP_BAD_GATEWAY; break;
        default:
            if (!d) break;
            if (ngx_queue_empty(&d->queue)) break;
            ngx_queue_t *q = ngx_queue_head(&d->queue);
            ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
            ngx_pq_query_t *query = qq->query;
            d->type = query->type;
            d->row++;
            if (ngx_pq_output(s, d, query, (const u_char *)buffer, len) != NGX_OK) rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }
    if (buffer) PQfreemem(buffer);
    return rc;
}
static ngx_int_t ngx_pq_res_default(ngx_pq_save_t *s, ngx_pq_data_t *d, PGresult *res) {
    char *value;
    if ((value = PQcmdStatus(res)) && ngx_strlen(value)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(res)), value); }
    else { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s", PQresStatus(PQresultStatus(res))); }
    if (s->count) { s->count--; return NGX_OK; }
    if (!d) return NGX_OK;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
    ngx_pq_query_t *query = qq->query;
    d->type = query->type;
    return NGX_HTTP_BAD_GATEWAY;
}
static ngx_int_t ngx_pq_res_fatal_error(ngx_pq_save_t *s, ngx_pq_data_t *d, PGresult *res) {
    char *value;
    if ((value = PQcmdStatus(res)) && ngx_strlen(value)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQresultErrorMessage(res), "%s and %s", PQresStatus(PQresultStatus(res)), value); }
    else { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQresultErrorMessage(res), "%s", PQresStatus(PQresultStatus(res))); }
    if (s->count) { s->count--; return NGX_OK; }
    if (!d) return NGX_OK;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
    ngx_pq_query_t *query = qq->query;
    d->type = query->type;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SEVERITY, offsetof(ngx_pq_error_t, severity)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SEVERITY_NONLOCALIZED, offsetof(ngx_pq_error_t, severity_nonlocalized)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SQLSTATE, offsetof(ngx_pq_error_t, sqlstate)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_MESSAGE_PRIMARY, offsetof(ngx_pq_error_t, message_primary)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_MESSAGE_DETAIL, offsetof(ngx_pq_error_t, message_detail)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_MESSAGE_HINT, offsetof(ngx_pq_error_t, message_hint)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_STATEMENT_POSITION, offsetof(ngx_pq_error_t, statement_position)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_INTERNAL_POSITION, offsetof(ngx_pq_error_t, internal_position)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_INTERNAL_QUERY, offsetof(ngx_pq_error_t, internal_query)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_CONTEXT, offsetof(ngx_pq_error_t, context)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SCHEMA_NAME, offsetof(ngx_pq_error_t, schema_name)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_TABLE_NAME, offsetof(ngx_pq_error_t, table_name)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_COLUMN_NAME, offsetof(ngx_pq_error_t, column_name)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_DATATYPE_NAME, offsetof(ngx_pq_error_t, datatype_name)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_CONSTRAINT_NAME, offsetof(ngx_pq_error_t, constraint_name)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SOURCE_FILE, offsetof(ngx_pq_error_t, source_file)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SOURCE_LINE, offsetof(ngx_pq_error_t, source_line)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_pq_copy_error(d, res, PG_DIAG_SOURCE_FUNCTION, offsetof(ngx_pq_error_t, source_function)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    return NGX_HTTP_BAD_GATEWAY;
}
static ngx_int_t ngx_pq_res_tuples_ok(ngx_pq_save_t *s, ngx_pq_data_t *d, PGresult *res) {
    char *value;
    if ((value = PQcmdStatus(res)) && ngx_strlen(value)) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_TUPLES_OK and %s", value); }
    else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_TUPLES_OK"); }
    if (s->count) { s->count--; return NGX_OK; }
    if (!d) return NGX_OK;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pq_query_queue_t *qq = ngx_queue_data(q, ngx_pq_query_queue_t, queue);
    ngx_pq_query_t *query = qq->query;
    d->type = query->type;
    if (query->header) {
        if (d->type & ngx_pq_type_location && d->row > 0) if (ngx_pq_output(s, d, query, (const u_char *)"\n", sizeof("\n") - 1) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        for (int col = 0; col < PQnfields(res); col++) {
            if (col > 0) if (ngx_pq_output(s, d, query, &query->delimiter, sizeof(query->delimiter)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            if (query->string && query->quote) if (ngx_pq_output(s, d, query, &query->quote, sizeof(query->quote)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            const u_char *data = (const u_char *)PQfname(res, col);
            ngx_uint_t len = ngx_strlen(data);
            if (query->string && query->quote && query->escape) for (ngx_uint_t k = 0; k < len; k++) {
                if (data[k] == query->quote) if (ngx_pq_output(s, d, query, &query->escape, sizeof(query->escape)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                if (ngx_pq_output(s, d, query, &data[k], sizeof(data[k])) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            } else {
                if (ngx_pq_output(s, d, query, (const u_char *)data, len) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (query->string && query->quote) if (ngx_pq_output(s, d, query, &query->quote, sizeof(query->quote)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    for (int row = 0; row < PQntuples(res); row++, d->row++) {
        if (row > 0 || query->header) if (ngx_pq_output(s, d, query, (const u_char *)"\n", sizeof("\n") - 1) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        for (int col = 0; col < PQnfields(res); col++) {
            if (col > 0) if (ngx_pq_output(s, d, query, &query->delimiter, sizeof(query->delimiter)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            if (PQgetisnull(res, row, col)) {
                if (query->null.len) if (ngx_pq_output(s, d, query, query->null.data, query->null.len) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            } else {
                if (query->string && query->quote) if (ngx_pq_output(s, d, query, &query->quote, sizeof(query->quote)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                const u_char *data = (const u_char *)PQgetvalue(res, row, col);
                ngx_uint_t len = PQgetlength(res, row, col);
                if (query->string && query->quote && query->escape) for (ngx_uint_t k = 0; k < len; k++) {
                    if (data[k] == query->quote) if (ngx_pq_output(s, d, query, &query->escape, sizeof(query->escape)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    if (ngx_pq_output(s, d, query, &data[k], sizeof(data[k])) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                } else {
                    if (ngx_pq_output(s, d, query, (const u_char *)data, len) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (query->string && query->quote) if (ngx_pq_output(s, d, query, &query->quote, sizeof(query->quote)) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    return NGX_OK;
}
static ngx_int_t ngx_pq_notify(ngx_pq_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_int_t rc = NGX_OK;
    ngx_pool_t *p;
    for (PGnotify *notify; (notify = PQnotifies(s->conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "relname=%s, extra=%s, be_pid=%i", notify->relname, notify->extra, notify->be_pid);
        if (!ngx_http_push_stream_add_msg_to_channel_my) continue;
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *)notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *)notify->extra };
        if (!(p = ngx_create_pool(4096 + id.len + text.len, s->connection->log))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_create_pool"); rc = NGX_ERROR; continue; }
        if (rc == NGX_OK) switch ((rc = ngx_http_push_stream_add_msg_to_channel_my(s->connection->log, &id, &text, NULL, NULL, 1, p))) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); break;
            case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED"); {
                for (ngx_queue_t *q = ngx_queue_head(&s->queue), *_; q != ngx_queue_sentinel(&s->queue) && (_ = ngx_queue_next(q)); q = _) {
                    ngx_pq_channel_queue_t *cq = ngx_queue_data(q, ngx_pq_channel_queue_t, queue);
                    if (cq->channel.len != id.len || ngx_strncmp(cq->channel.data, id.data, id.len)) continue;
                    ngx_queue_remove(q);
                    break;
                }
                if (PQpipelineStatus(s->conn) == PQ_PIPELINE_OFF) if (!PQenterPipelineMode(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQenterPipelineMode"); rc = NGX_ERROR; goto destroy; }
                PQExpBufferData sql;
                initPQExpBuffer(&sql);
                appendPQExpBufferStr(&sql, "UNLISTEN ");
                char *str;
                if (!(str = PQescapeIdentifier(s->conn, (char *)id.data, id.len))) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQescapeIdentifier"); rc = NGX_ERROR; goto term; }
                appendPQExpBufferStr(&sql, str);
                PQfreemem(str);
                if (PQExpBufferDataBroken(sql)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "PQExpBufferDataBroken"); rc = NGX_ERROR; goto term; }
                if (!PQsendQueryParams(s->conn, sql.data, 0, NULL, NULL, NULL, NULL, 0)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQsendQueryParams"); rc = NGX_ERROR; goto term; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQsendQueryParams('%s')", sql.data);
                s->count++;
                rc = NGX_OK;
term:
                termPQExpBuffer(&sql);
            } break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DONE"); rc = NGX_OK; break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_OK"); break;
            default: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == %i", rc); break;
        }
destroy:
        ngx_destroy_pool(p);
    }
    if (PQpipelineStatus(s->conn) == PQ_PIPELINE_ON) if (!PQpipelineSync(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQpipelineSync"); rc = NGX_ERROR; }
    return rc;
}
static ngx_int_t ngx_pq_queries(ngx_pq_save_t *s, ngx_pq_data_t *d, ngx_uint_t type) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_connection_t *c = s->connection;
    c->read->active = 0;
    c->write->active = 0;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_int_t rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    PQExpBufferData name;
    PQExpBufferData sql;
    initPQExpBuffer(&name);
    initPQExpBuffer(&sql);
    if (!PQenterPipelineMode(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQenterPipelineMode"); goto ret; }
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_array_t *queries = &plcf->queries;
    if (uscf->srv_conf && type & ngx_pq_type_upstream) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
        if (pscf->queries.elts) queries = &pscf->queries;
    }
    if (!queries->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!queries->nelts"); goto ret; }
    ngx_pq_query_t *query = queries->elts;
    for (ngx_uint_t i = 0; i < queries->nelts; i++) {
        ngx_pq_query_queue_t *qq;
        if (!(qq = ngx_pcalloc(r->pool, sizeof(*qq)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pcalloc"); goto ret; }
        qq->query = &query[i];
        ngx_queue_insert_tail(&d->queue, &qq->queue);
        ngx_pq_argument_t *argument = query[i].arguments.elts;
        if (!(qq->paramTypes = ngx_pcalloc(r->pool, query[i].arguments.nelts * sizeof(*qq->paramTypes)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pcalloc"); goto ret; }
        if (!(qq->paramValues = ngx_pcalloc(r->pool, query[i].arguments.nelts * sizeof(*qq->paramValues)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pcalloc"); goto ret; }
        for (ngx_uint_t j = 0; j < query[i].arguments.nelts; j++) {
            if (query[i].type & (ngx_pq_type_query|ngx_pq_type_prepare)) {
                if (argument[j].oid.complex.value.data) {
                    ngx_str_t value;
                    if (ngx_http_complex_value(r, &argument[j].oid.complex, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
                    ngx_int_t n = ngx_atoi(value.data, value.len);
                    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_atoi == NGX_ERROR"); goto ret; }
                    argument[j].oid.value = n;
                }
                qq->paramTypes[j] = argument[j].oid.value;
            }
            if (query[i].type & (ngx_pq_type_query|ngx_pq_type_execute)) {
                if (argument[j].value.complex.value.data) {
                    ngx_str_t value;
                    if (ngx_http_complex_value(r, &argument[j].value.complex, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
                    argument[j].value.str = value;
                }
                if (!(qq->paramValues[j] = ngx_pnalloc(r->pool, argument[j].value.str.len + 1))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); goto ret; }
                (void)ngx_cpystrn((u_char *)qq->paramValues[j], argument[j].value.str.data, argument[j].value.str.len + 1);
            }
        }
        resetPQExpBuffer(&sql);
        ngx_pq_command_t *command = query[i].commands.elts;
        for (ngx_uint_t j = 0; j < query[i].commands.nelts; j++) if (command[j].index) {
            char *str;
            ngx_http_variable_value_t *value;
            if (!(value = ngx_http_get_indexed_variable(r, command[j].index))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_http_get_indexed_variable"); goto ret; }
            if (!(str = PQescapeIdentifier(s->conn, (char *)value->data, value->len))) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQescapeIdentifier"); goto ret; }
            appendPQExpBufferStr(&sql, str);
            PQfreemem(str);
        } else appendBinaryPQExpBuffer(&sql, (char *)command[j].str.data, command[j].str.len);
        if (PQExpBufferDataBroken(sql)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "PQExpBufferDataBroken"); goto ret; }
        if (query[i].type & ngx_pq_type_query) {
            if (!PQsendQueryParams(s->conn, sql.data, query[i].arguments.nelts, qq->paramTypes, qq->paramValues, NULL, NULL, 0)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQsendQueryParams"); rc = NGX_HTTP_BAD_GATEWAY; goto ret; }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQsendQueryParams('%s')", sql.data);
        } else {
            resetPQExpBuffer(&name);
            if (query[i].name.complex.value.data) {
                ngx_str_t value;
                if (ngx_http_complex_value(r, &query[i].name.complex, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto ret; }
                appendBinaryPQExpBuffer(&name, (char *)value.data, value.len);
            } else appendBinaryPQExpBuffer(&name, (char *)query[i].name.str.data, query[i].name.str.len);
            if (PQExpBufferDataBroken(name)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "PQExpBufferDataBroken"); goto ret; }
            if (query[i].type & ngx_pq_type_prepare) {
                if (!PQsendPrepare(s->conn, name.data, sql.data, query[i].arguments.nelts, qq->paramTypes)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQsendPrepare"); rc = NGX_HTTP_BAD_GATEWAY; goto ret; }
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQsendPrepare('%s', '%s')", name.data, sql.data);
            } else if (query[i].type & ngx_pq_type_execute) {
                if (!PQsendQueryPrepared(s->conn, name.data, query[i].arguments.nelts, qq->paramValues, NULL, NULL, 0)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQsendQueryPrepared"); rc = NGX_HTTP_BAD_GATEWAY; goto ret; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQsendQueryPrepared('%s')", name.data);
            }
        }
    }
    if (!PQpipelineSync(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQpipelineSync"); goto ret; }
    c->read->active = 1;
    c->write->active = 0;
    rc = NGX_AGAIN;
ret:
    termPQExpBuffer(&name);
    termPQExpBuffer(&sql);
    d->row = 0;
    return rc;
}

static ngx_int_t ngx_pq_poll(ngx_pq_save_t *s, ngx_pq_data_t *d) {
    ngx_connection_t *c = s->connection;
    for (;;) switch (PQconnectPoll(s->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_ACTIVE"); return NGX_AGAIN;
        case PGRES_POLLING_FAILED: ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "PGRES_POLLING_FAILED"); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_OK"); return ngx_pq_queries(s, d, ngx_pq_type_location|ngx_pq_type_upstream);
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_READING"); c->read->active = 1; c->write->active = 0; return NGX_AGAIN;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_WRITING"); c->read->active = 0; c->write->active = 1; break;
    }
    return NGX_AGAIN;
}
static ngx_int_t ngx_pq_result(ngx_pq_save_t *s, ngx_pq_data_t *d) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (!PQconsumeInput(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQconsumeInput"); return NGX_HTTP_BAD_GATEWAY; }
    ngx_int_t rc = NGX_OK;
    for (PGresult *res; ((res = PQgetResult(s->conn)) || (res = PQgetResult(s->conn))); PQclear(res)) switch (PQresultStatus(res)) {
        case PGRES_COMMAND_OK: rc = ngx_pq_res_command_ok(s, d, res); break;
        case PGRES_COPY_OUT: rc = ngx_pq_res_copy_out(s, d); break;
        case PGRES_FATAL_ERROR: rc = ngx_pq_res_fatal_error(s, d, res); break;
        case PGRES_PIPELINE_SYNC: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_PIPELINE_SYNC"); break;
        case PGRES_TUPLES_OK: rc = ngx_pq_res_tuples_ok(s, d, res); break;
        default: rc = ngx_pq_res_default(s, d, res); break;
    }
    if (!PQexitPipelineMode(s->conn)) { ngx_pq_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessage(s->conn), "!PQexitPipelineMode"); return NGX_HTTP_BAD_GATEWAY; }
    if (rc == NGX_OK) rc = ngx_pq_notify(s);
    if (s->count) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "s->count = %i", s->count); return NGX_HTTP_BAD_GATEWAY; }
    if (!d) return rc;
    if (!ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_queue_empty"); return NGX_HTTP_BAD_GATEWAY; }
    if (rc == NGX_OK && d->type & ngx_pq_type_upstream) return ngx_pq_queries(s, d, ngx_pq_type_location);
    if (s->conn->inBufSize > s->inBufSize) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "inBufSize %i > %i", s->conn->inBufSize, s->inBufSize);
        char *newbuf;
        if (!(newbuf = realloc(s->conn->inBuffer, s->inBufSize))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!realloc"); return NGX_HTTP_BAD_GATEWAY; }
        s->conn->inBuffer = newbuf;
        s->conn->inBufSize = s->inBufSize;
    }
    return rc;
}

static void ngx_pq_save_cln_handler(void *data) {
    ngx_pq_save_t *s = data;
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%V", &c->addr_text);
    if (s->conn) PQfinish(s->conn);
    s->conn = NULL;
    if (!ngx_terminate && !ngx_exiting && !c->error) while (!ngx_queue_empty(&s->queue)) {
        ngx_queue_t *q = ngx_queue_head(&s->queue);
        ngx_pq_channel_queue_t *cq = ngx_queue_data(q, ngx_pq_channel_queue_t, queue);
        ngx_queue_remove(q);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "channel = %V", &cq->channel);
        (void)ngx_http_push_stream_delete_channel_my(c->log, &cq->channel, NULL, 0, c->pool);
    }
}
static void ngx_pq_notice_processor(void *arg, const char *message) {
    ngx_pq_save_t *s = arg;
    ngx_pq_log_error(NGX_LOG_NOTICE, s->connection->log, 0, message, "PGRES_NONFATAL_ERROR");
}

static ngx_int_t ngx_pq_peer_open(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pq_data_t *d = data;
    ngx_pq_save_t *s;
    ngx_http_request_t *r = d->request;
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    size_t buffer_size = plcf->upstream.buffer_size;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_pq_connect_t *connect = &plcf->connect;
    if (uscf->srv_conf) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
        buffer_size = pscf->buffer_size;
        connect = &pscf->connect;
    }
    plcf->upstream.connect_timeout = connect->timeout;
    PQExpBufferData conninfo;
    initPQExpBuffer(&conninfo);
    ngx_str_t *option = connect->options.elts;
    for (ngx_uint_t i = 0; i < connect->options.nelts; i++) {
        if (i) appendPQExpBufferChar(&conninfo, ' ');
        appendBinaryPQExpBuffer(&conninfo, (char *)option[i].data, option[i].len);
    }
    if (pc->sockaddr->sa_family != AF_UNIX) {
        appendPQExpBufferStr(&conninfo, " host=");
        ngx_http_upstream_server_t *us = uscf->servers->elts;
        ngx_str_t host = uscf->host;
        for (ngx_uint_t j = 0; j < uscf->servers->nelts; j++) if (us[j].name.data) for (ngx_uint_t k = 0; k < us[j].naddrs; k++) if (pc->sockaddr == us[j].addrs[k].sockaddr) { host = us[j].name; goto found; }
found:
        while (host.len--) if (host.data[host.len] == ':') break;
        appendBinaryPQExpBuffer(&conninfo, (char *)host.data, host.len);
    }
    ngx_str_t host = *pc->name;
    ngx_str_t port = host;
    while (host.len--) if (host.data[host.len] == ':') break;
    port.data += host.len + 1;
    port.len -= host.len + 1;
    if (pc->sockaddr->sa_family != AF_UNIX) {
        appendPQExpBufferStr(&conninfo, " hostaddr=");
        appendBinaryPQExpBuffer(&conninfo, (char *)host.data, host.len);
    } else {
        appendPQExpBufferStr(&conninfo, " host=");
        appendBinaryPQExpBuffer(&conninfo, (char *)host.data + 5, host.len - 5);
    }
    appendPQExpBufferStr(&conninfo, " port=");
    appendBinaryPQExpBuffer(&conninfo, (char *)port.data, port.len);
    ngx_int_t rc = NGX_ERROR;
    if (PQExpBufferDataBroken(conninfo)) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQExpBufferDataBroken"); goto term; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", conninfo.data);
    PGconn *conn = PQconnectStart(conninfo.data);
    if (PQstatus(conn) == CONNECTION_BAD) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessage(conn), "CONNECTION_BAD"); goto finish; }
    (void)PQsetErrorContextVisibility(conn, connect->show_context);
    (void)PQsetErrorVerbosity(conn, connect->errors);
    if (PQsetnonblocking(conn, 1) == -1) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessage(conn), "PQsetnonblocking == -1"); goto finish; }
    int fd;
    if ((fd = PQsocket(conn)) < 0) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQsocket < 0"); goto finish; }
    ngx_connection_t *c = ngx_get_connection(fd, pc->log);
    if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_get_connection"); goto finish; }
    c->addr_text = *pc->name;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->read->log = pc->log;
    c->shared = 1;
    c->start_time = ngx_current_msec;
    c->type = pc->type ? pc->type : SOCK_STREAM;
    c->write->log = pc->log;
    if (!c->pool && !(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); goto close; }
    if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    s->inBufSize = ngx_max(conn->inBufSize, (int)buffer_size);
    (void)PQsetNoticeProcessor(conn, ngx_pq_notice_processor, s);
    ngx_queue_init(&s->queue);
    ngx_pool_cleanup_t *cln;
    if (!(cln = ngx_pool_cleanup_add(c->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); goto destroy; }
    cln->data = s;
    cln->handler = ngx_pq_save_cln_handler;
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_conn != NGX_OK"); goto destroy; }
    } else {
        if (ngx_add_event(c->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
    }
    pc->connection = c;
    rc = NGX_AGAIN;
    s->conn = conn;
    s->connection = c;
    goto term;
destroy:
    ngx_destroy_pool(c->pool);
close:
    ngx_close_connection(c);
finish:
    PQfinish(conn);
term:
    termPQExpBuffer(&conninfo);
    return rc;
}

static void ngx_pq_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    for (ngx_pool_cleanup_t *cln = c->pool->cleanup; cln; cln = cln->next) if (cln->handler == ngx_pq_save_cln_handler) {
        ngx_pq_save_t *s = cln->data;
        if (!ngx_terminate && !ngx_exiting && !c->error && !ev->error && !ev->timedout) {
            if (s->timeout) ngx_add_timer(c->read, s->timeout);
            if (ngx_pq_result(s, NULL) == NGX_OK) return;
        }
        s->read(ev);
    }
}
static void ngx_pq_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    for (ngx_pool_cleanup_t *cln = c->pool->cleanup; cln; cln = cln->next) if (cln->handler == ngx_pq_save_cln_handler) {
        ngx_pq_save_t *s = cln->data;
        s->write(ev);
    }
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
    ngx_connection_t *c = pc->connection;
    for (ngx_pool_cleanup_t *cln = c->pool->cleanup; cln; cln = cln->next) if (cln->handler == ngx_pq_save_cln_handler) {
        ngx_pq_save_t *s = d->save = cln->data;
//        if (PQstatus(s->conn) != CONNECTION_OK) { ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessage(s->conn), "CONNECTION_BAD"); return NGX_ERROR; }
        return ngx_pq_queries(s, d, ngx_pq_type_location);
    }
    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!s");
    return NGX_ERROR;
}
static void ngx_pq_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %ui", state);
    ngx_pq_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_pq_save_t *s = d->save;
    if (!s) return;
    if (!ngx_queue_empty(&d->queue)) {
        while (!ngx_queue_empty(&d->queue)) {
            ngx_queue_t *q = ngx_queue_head(&d->queue);
            ngx_queue_remove(q);
            s->count++;
        }
        PGcancel *cancel;
        if (s->conn && (cancel = PQgetCancel(s->conn))) {
            char errbuf[256];
            if (!PQcancel(cancel, errbuf, sizeof(errbuf))) ngx_pq_log_error(NGX_LOG_ERR, pc->log, 0, errbuf, "!PQcancel");
            PQfreeCancel(cancel);
        }
    }
    if (pc->connection) return;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
    if (!pscf) return;
    ngx_connection_t *c = s->connection;
    if (!c) return;
    if (c->read->timer_set) s->timeout = c->read->timer.key - ngx_current_msec;
    s->read = c->read->handler;
    s->write = c->write->handler;
    c->read->handler = ngx_pq_read_handler;
    c->write->handler = ngx_pq_write_handler;
    if (!pscf->log) return;
    c->log = pscf->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;
}

static ngx_int_t ngx_pq_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    ngx_pq_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_queue_init(&d->queue);
    if (uscf->srv_conf) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
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
    return NGX_OK;
}

static ngx_int_t ngx_pq_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    if (uscf->srv_conf) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
        if (pscf->peer.init_upstream(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "peer.init_upstream != NGX_OK"); return NGX_ERROR; }
        pscf->peer.init = uscf->peer.init ? uscf->peer.init : ngx_http_upstream_init_round_robin_peer;
        ngx_conf_init_size_value(pscf->buffer_size, (size_t)ngx_pagesize);
    } else {
        if (ngx_http_upstream_init_round_robin(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_http_upstream_init_round_robin != NGX_OK"); return NGX_ERROR; }
    }
    uscf->peer.init = ngx_pq_peer_init;
    return NGX_OK;
}

static void ngx_pq_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    ngx_connection_t *c = s->connection;
    ngx_int_t rc = NGX_AGAIN;
    switch (PQstatus(s->conn)) {
        case CONNECTION_AUTH_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_AUTH_OK"); break;
        case CONNECTION_AWAITING_RESPONSE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_AWAITING_RESPONSE"); break;
        case CONNECTION_BAD: ngx_pq_log_error(NGX_LOG_ERR, r->connection->log, 0, PQerrorMessage(s->conn), "CONNECTION_BAD"); rc = NGX_ERROR; goto ret;
        case CONNECTION_CHECK_STANDBY: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_CHECK_STANDBY"); break;
        case CONNECTION_CHECK_TARGET: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_CHECK_TARGET"); break;
        case CONNECTION_CHECK_WRITABLE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_CHECK_WRITABLE"); break;
        case CONNECTION_CONSUME: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_CONSUME"); break;
        case CONNECTION_GSS_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_GSS_STARTUP"); break;
        case CONNECTION_MADE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_MADE"); break;
        case CONNECTION_NEEDED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_NEEDED"); break;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_OK");
            if (c->read->timedout || c->write->timedout) return ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
            rc = ngx_pq_result(s, d);
            goto ret;
        case CONNECTION_SETENV: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_SETENV"); break;
        case CONNECTION_SSL_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_SSL_STARTUP"); break;
        case CONNECTION_STARTED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_STARTED"); break;
    }
    if (c->read->timedout || c->write->timedout) return ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    rc = ngx_pq_poll(s, d);
ret:
    switch (rc) {
        case NGX_ERROR: ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); break;
        case NGX_AGAIN: break;
        default: ngx_http_upstream_finalize_request(r, u, rc); break;
    }
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
    if (!plcf->queries.nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!queries"); return NGX_ERROR; }
    u->request_sent = 1; // force to reinit_request
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
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) return;
    if (!r->headers_out.status) r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    for (ngx_chain_t *cl = u->out_bufs; cl; cl = cl->next) r->headers_out.content_length_n += cl->buf->last - cl->buf->pos;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return;
    u->header_sent = 1;
    if (!u->out_bufs) return;
    if (ngx_http_output_filter(r, u->out_bufs) != NGX_OK) return;
    ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs, &u->out_bufs, u->output.tag);
}
static ngx_int_t ngx_pq_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return NGX_OK;
}
static ngx_int_t ngx_pq_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    r->state = 0;
    u->read_event_handler = ngx_pq_event_handler;
    u->write_event_handler = ngx_pq_event_handler;
    return NGX_OK;
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
    ngx_array_t *variables;
    ngx_pq_variable_t *variable;
    variables = &d->variables;
    variable = variables->elts;
    for (ngx_uint_t i = 0; i < variables->nelts; i++) if (variable[i].index == index) {
        for (ngx_chain_t *cl = variable[i].cl; cl; cl = cl->next) v->len += cl->buf->last - cl->buf->pos;
        u_char *p;
        if (!(p = v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_chain_t *cl = variable[i].cl; cl; cl = cl->next) p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        v->no_cacheable = 0;
        v->not_found = 0;
        v->valid = 1;
        return NGX_OK;
    }
    variables = &s->variables;
    variable = variables->elts;
    for (ngx_uint_t i = 0; i < variables->nelts; i++) if (variable[i].index == index) {
        for (ngx_chain_t *cl = variable[i].cl; cl; cl = cl->next) v->len += cl->buf->last - cl->buf->pos;
        u_char *p;
        if (!(p = v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_chain_t *cl = variable[i].cl; cl; cl = cl->next) p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        v->no_cacheable = 0;
        v->not_found = 0;
        v->valid = 1;
        return NGX_OK;
    }
    return NGX_OK;
}

typedef char *(*pq_func)(const PGconn *conn);
static ngx_int_t ngx_pq_conn_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return NGX_OK;
    pq_func function = (pq_func)data;
    if (!(v->data = (u_char *)function(s->conn))) return NGX_OK;
    v->len = ngx_strlen(v->data);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}
static ngx_int_t ngx_pq_error_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_str_t *error = (ngx_str_t *)((u_char *)&d->error + data);
    if (!error->len) return NGX_OK;
    v->data = error->data;
    v->len = error->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}
static ngx_int_t ngx_pq_parameter_status_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return NGX_OK;
    if (!(v->data = PQparameterStatus(s->conn, (char *)data))) return NGX_OK;
    v->len = ngx_strlen(v->data);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}
static ngx_int_t ngx_pq_pid_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return NGX_OK;
    if (!(v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_sprintf(v->data, "%uD", PQbackendPID(s->conn)) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}
static ngx_int_t ngx_pq_ssl_attribute_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return NGX_OK;
    if (!(v->data = PQsslAttribute(s->conn, (char *)data))) return NGX_OK;
    v->len = ngx_strlen(v->data);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}
static ngx_int_t ngx_pq_transaction_status_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pq_peer_get) return NGX_OK;
    ngx_pq_data_t *d = u->peer.data;
    ngx_pq_save_t *s = d->save;
    if (!s) return NGX_OK;
    switch (PQtransactionStatus(s->conn)) {
        case PQTRANS_ACTIVE: ngx_str_set(v, "ACTIVE"); break;
        case PQTRANS_IDLE: ngx_str_set(v, "IDLE"); break;
        case PQTRANS_INERROR: ngx_str_set(v, "INERROR"); break;
        case PQTRANS_INTRANS: ngx_str_set(v, "INTRANS"); break;
        case PQTRANS_UNKNOWN: ngx_str_set(v, "UNKNOWN"); break;
    }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static const ngx_http_variable_t ngx_pq_variables[] = {
  { ngx_string("pq_application_name"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"application_name", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_cipher"), NULL, ngx_pq_ssl_attribute_get_handler, (uintptr_t)"key_cipher", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_client_encoding"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"client_encoding", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_column_name"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, column_name), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_compression"), NULL, ngx_pq_ssl_attribute_get_handler, (uintptr_t)"key_compression", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_constraint_name"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, constraint_name), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_context"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, context), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_datatype_name"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, datatype_name), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_datestyle"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"DateStyle", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_db"), NULL, ngx_pq_conn_get_handler, (uintptr_t)PQdb, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_default_transaction_read_only"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"default_transaction_read_only", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_hostaddr"), NULL, ngx_pq_conn_get_handler, (uintptr_t)PQhostaddr, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_host"), NULL, ngx_pq_conn_get_handler, (uintptr_t)PQhost, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_in_hot_standby"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"in_hot_standby", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_integer_datetimes"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"integer_datetimes", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_internal_position"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, internal_position), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_internal_query"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, internal_query), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_intervalstyle"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"IntervalStyle", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_is_superuser"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"is_superuser", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_key_bits"), NULL, ngx_pq_ssl_attribute_get_handler, (uintptr_t)"key_bits", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_library"), NULL, ngx_pq_ssl_attribute_get_handler, (uintptr_t)"library", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_message_detail"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, message_detail), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_message_hint"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, message_hint), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_message_primary"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, message_primary), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_options"), NULL, ngx_pq_conn_get_handler, (uintptr_t)PQoptions, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_pid"), NULL, ngx_pq_pid_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_port"), NULL, ngx_pq_conn_get_handler, (uintptr_t)PQport, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_protocol"), NULL, ngx_pq_ssl_attribute_get_handler, (uintptr_t)"protocol", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_schema_name"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, schema_name), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_server_encoding"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"server_encoding", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_server_version"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"server_version", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_session_authorization"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"session_authorization", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_severity_nonlocalized"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, severity_nonlocalized), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_severity"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, severity), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_source_file"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, source_file), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_source_function"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, source_function), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_source_line"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, source_line), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_sqlstate"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, sqlstate), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_standard_conforming_strings"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"standard_conforming_strings", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_statement_position"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, statement_position), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_table_name"), NULL, ngx_pq_error_get_handler, offsetof(ngx_pq_error_t, table_name), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_timezone"), NULL, ngx_pq_parameter_status_get_handler, (uintptr_t)"TimeZone", NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_transaction_status"), NULL, ngx_pq_transaction_status_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pq_user"), NULL, ngx_pq_conn_get_handler, (uintptr_t)PQuser, NGX_HTTP_VAR_CHANGEABLE, 0 },
    ngx_http_null_variable
};

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

static char *ngx_pq_argument_output_loc_conf(ngx_conf_t *cf, ngx_pq_query_t *query) {
    ngx_str_t *str = cf->args->elts;
    for (ngx_uint_t i = query->type & ngx_pq_type_prepare ? 3 : 2; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("delimiter=") - 1))) return "empty \"delimiter\" value";
            if (str[i].len - (sizeof("delimiter=") - 1) > 1) return "\"delimiter\" value must be one character";
            query->delimiter = str[i].data[sizeof("delimiter=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("escape=") - 1))) { query->escape = '\0'; continue; }
            else if (str[i].len > 1) return "\"escape\" value must be one character";
            query->escape = str[i].data[sizeof("escape=") - 1];
            continue;
        }
        if (str[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("header=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("header=") - 1], str[i].len - (sizeof("header=") - 1))) break;
            if (!e[j].name.len) return "\"header\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            query->header = e[j].value;
            continue;
        }
        if (str[i].len > sizeof("output=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"output=", sizeof("output=") - 1)) {
            if (str[i].data[sizeof("output=") - 1] == '$' && query->type & ngx_pq_type_upstream) {
                ngx_str_t name = str[i];
                name.data += sizeof("output=") - 1 + 1;
                name.len -= sizeof("output=") - 1 + 1;
                ngx_http_variable_t *variable;
                if (!(variable = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE))) return "!ngx_http_add_variable";
                if ((query->index = ngx_http_get_variable_index(cf, &name)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
                variable->get_handler = ngx_pq_variable_get_handler;
                variable->data = query->index;
                continue;
            }
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("csv"), ngx_pq_output_csv }, { ngx_string("plain"), ngx_pq_output_plain }, { ngx_string("value"), ngx_pq_output_value }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
            if (!e[j].name.len) return "\"output\" value must be \"csv\", \"plain\" or \"value\"";
            query->output = e[j].value;
            switch (query->output) {
                case ngx_pq_output_csv: {
                    ngx_str_set(&query->null, "");
                    query->delimiter = ',';
                    query->escape = '"';
                    query->header = 1;
                    query->quote = '"';
                } break;
                case ngx_pq_output_plain: {
                    ngx_str_set(&query->null, "\\N");
                    query->delimiter = '\t';
                    query->header = 1;
                } break;
                default: break;
            }
            continue;
        }
        if (str[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            if (!(query->null.len = str[i].len - (sizeof("null=") - 1))) return "empty \"null\" value";
            query->null.data = &str[i].data[sizeof("null=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("quote=") - 1))) { query->quote = '\0'; continue; }
            else if (str[i].len - (sizeof("quote=") - 1) > 1) return "\"quote\" value must be one character";
            query->quote = str[i].data[sizeof("quote=") - 1];
            continue;
        }
        if (str[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            if (!(query->type & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("string=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("string=") - 1], str[i].len - (sizeof("string=") - 1))) break;
            if (!e[j].name.len) return "\"string\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            query->string = e[j].value;
            continue;
        }
        ngx_pq_argument_t *argument;
        if (!query->arguments.elts && ngx_array_init(&query->arguments, cf->pool, 1, sizeof(*argument)) != NGX_OK) return "ngx_array_init != NGX_OK";
        if (!(argument = ngx_array_push(&query->arguments))) return "!ngx_array_push";
        ngx_memzero(argument, sizeof(*argument));
        ngx_str_t value = str[i];
        ngx_str_t oid = ngx_null_string;
        if (query->type & ngx_pq_type_query) {
            u_char *colon;
            if ((colon = ngx_strstrn(value.data, "::", sizeof("::") - 1 - 1))) {
                value.len = colon - value.data;
                oid.data = colon + sizeof("::") - 1;
                oid.len = str[i].len - value.len - sizeof("::") + 1;
            }
        } else if (query->type & ngx_pq_type_prepare) oid = value;
        if (!(query->type & ngx_pq_type_prepare)) {
            if (ngx_http_script_variables_count(&value)) {
                ngx_http_compile_complex_value_t ccv = {cf, &value, &argument->value.complex, 0, 0, 0};
                if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
            } else argument->value.str = value;
        }
        if (!oid.len) continue;
        if (ngx_http_script_variables_count(&oid)) {
            ngx_http_compile_complex_value_t ccv = {cf, &oid, &argument->oid.complex, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
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
    if (ngx_http_script_variables_count(&str[1])) {
        ngx_http_compile_complex_value_t ccv = {cf, &str[1], &query->name.complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    } else query->name.str = str[1];
    query->type = cmd->offset;
    return ngx_pq_argument_output_loc_conf(cf, query);
}
static char *ngx_pq_option_loc_ups_conf(ngx_conf_t *cf, ngx_pq_connect_t *connect) {
    if (connect->options.elts) return "is duplicate";
    ngx_str_t *option;
    if (ngx_array_init(&connect->options, cf->pool, cf->args->nelts - 1, sizeof(*option)) != NGX_OK) return "ngx_array_init != NGX_OK";
    ngx_str_t application_name = ngx_null_string;
    ngx_str_t *str = cf->args->elts;
    connect->errors = PQERRORS_DEFAULT;
    connect->show_context = PQSHOW_CONTEXT_ERRORS;
    connect->timeout = 60 * 1000;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("host=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"host=", sizeof("host=") - 1)) return "\"host\" option not allowed!";
        if (str[i].len > sizeof("hostaddr=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"hostaddr=", sizeof("hostaddr=") - 1)) return "\"hostaddr\" option not allowed!";
        if (str[i].len > sizeof("port=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"port=", sizeof("port=") - 1)) return "\"port\" option not allowed!";
        if (str[i].len > sizeof("errors=") - 1 && !ngx_strncmp(str[i].data, (u_char *)"errors=", sizeof("errors=") - 1)) {
            str[i].data += sizeof("errors=") - 1;
            str[i].len -= sizeof("errors=") - 1;
            static const ngx_conf_enum_t e[] = { { ngx_string("default"), PQERRORS_DEFAULT }, { ngx_string("sqlstate"), PQERRORS_SQLSTATE }, { ngx_string("terse"), PQERRORS_TERSE }, { ngx_string("verbose"), PQERRORS_VERBOSE }, { ngx_null_string, 0 } };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len && !ngx_strncmp(e[j].name.data, str[i].data, str[i].len))  break;
            if (!e[j].name.len) return "\"errors\" value must be \"default\", \"sqlstate\", \"terse\" or \"verbose\"";
            connect->errors = e[j].value;
            continue;
        }
        if (str[i].len > sizeof("show_context=") - 1 && !ngx_strncmp(str[i].data, (u_char *)"show_context=", sizeof("show_context=") - 1)) {
            str[i].data += sizeof("show_context=") - 1;
            str[i].len -= sizeof("show_context=") - 1;
            static const ngx_conf_enum_t e[] = { { ngx_string("always"), PQSHOW_CONTEXT_ALWAYS }, { ngx_string("errors"), PQSHOW_CONTEXT_ERRORS }, { ngx_string("never"), PQSHOW_CONTEXT_NEVER }, { ngx_null_string, 0 } };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len && !ngx_strncmp(e[j].name.data, str[i].data, str[i].len))  break;
            if (!e[j].name.len) return "\"show_context\" value must be \"always\", \"errors\", or \"never\"";
            connect->show_context = e[j].value;
            continue;
        }
        if (str[i].len > sizeof("connect_timeout=") - 1 && !ngx_strncmp(str[i].data, (u_char *)"connect_timeout=", sizeof("connect_timeout=") - 1)) {
            str[i].data += sizeof("connect_timeout=") - 1;
            str[i].len -= sizeof("connect_timeout=") - 1;
            ngx_int_t n = ngx_parse_time(&str[i], 0);
            if (n == NGX_ERROR) return "ngx_parse_time == NGX_ERROR";
            connect->timeout = (ngx_msec_t)n;
            continue;
        }
        if (str[i].len > sizeof("application_name=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"application_name=", sizeof("application_name=") - 1)) application_name = str[i];
        else if (str[i].len > sizeof("fallback_application_name=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"fallback_application_name=", sizeof("fallback_application_name=") - 1)) application_name = str[i];
        if (!(option = ngx_array_push(&connect->options))) return "!ngx_array_push";
        ngx_memzero(option, sizeof(*option));
        *option = str[i];
    }
    if (!application_name.data) {
        if (!(option = ngx_array_push(&connect->options))) return "!ngx_array_push";
        ngx_memzero(option, sizeof(*option));
        ngx_str_set(option, "application_name=nginx");
    }
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
    if (query->type & ngx_pq_type_prepare) {
        if (ngx_http_script_variables_count(&str[i])) {
            ngx_http_compile_complex_value_t ccv = {cf, &str[i], &query->name.complex, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
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
    return ngx_pq_argument_output_loc_conf(cf, query);
}

static ngx_int_t ngx_pq_preconfiguration(ngx_conf_t *cf) {
    ngx_http_variable_t *var;
    for (ngx_http_variable_t *v = ngx_pq_variables; v->name.len; v++) {
        if (!(var = ngx_http_add_variable(cf, &v->name, v->flags))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_http_add_variable"); return NGX_ERROR; }
        *var = *v;
    }
    return NGX_OK;
}
static void *ngx_pq_create_srv_conf(ngx_conf_t *cf) {
    ngx_pq_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) return NULL;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    return conf;
}
static void *ngx_pq_create_loc_conf(ngx_conf_t *cf) {
    ngx_pq_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) return NULL;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    ngx_str_set(&conf->upstream.module, "pq");
    return conf;
}
static char *ngx_pq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pq_loc_conf_t *prev = parent;
    ngx_pq_loc_conf_t *conf = child;
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t)ngx_pagesize);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.pass_request_body, prev->upstream.pass_request_body, 0);
    ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 1);
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    return NGX_CONF_OK;
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
static char *ngx_pq_option_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    return ngx_pq_option_loc_ups_conf(cf, &plcf->connect);
}
static char *ngx_pq_option_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (uscf->peer.init_upstream != ngx_pq_peer_init_upstream) {
        pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
        uscf->peer.init_upstream = ngx_pq_peer_init_upstream;
    }
    return ngx_pq_option_loc_ups_conf(cf, &pscf->connect);
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
    if (!plcf->connect.options.elts) url.no_resolve = 1;
    url.url = str[1];
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) return NGX_CONF_ERROR;
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pq_peer_init_upstream;
    return NGX_CONF_OK;
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

static ngx_http_module_t ngx_pq_ctx = {
    .preconfiguration = ngx_pq_preconfiguration,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pq_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_pq_create_loc_conf,
    .merge_loc_conf = ngx_pq_merge_loc_conf
};
static ngx_command_t ngx_pq_commands[] = {
  { ngx_string("pq_buffer_size"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.buffer_size), NULL },
  { ngx_string("pq_buffer_size"), NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1, ngx_conf_set_size_slot, NGX_HTTP_SRV_CONF_OFFSET, offsetof(ngx_pq_srv_conf_t, buffer_size), NULL },
  { ngx_string("pq_execute"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_execute_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_execute|ngx_pq_type_output, NULL },
  { ngx_string("pq_execute"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_execute_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_execute, NULL },
  { ngx_string("pq_ignore_client_abort"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.ignore_client_abort), NULL },
  { ngx_string("pq_log"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_log_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_next_upstream"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.next_upstream), &ngx_pq_next_upstream_masks },
  { ngx_string("pq_next_upstream_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.next_upstream_timeout), NULL },
  { ngx_string("pq_next_upstream_tries"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.next_upstream_tries), NULL },
  { ngx_string("pq_option"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_option_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_option"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_option_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_pass"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1, ngx_pq_pass_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_pass_request_body"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.pass_request_body), NULL },
  { ngx_string("pq_prepare"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_prepare_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_prepare, NULL },
  { ngx_string("pq_prepare"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_prepare_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_prepare, NULL },
  { ngx_string("pq_query"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_query_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_query|ngx_pq_type_output, NULL },
  { ngx_string("pq_query"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_query_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_query, NULL },
  { ngx_string("pq_request_buffering"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pq_loc_conf_t, upstream.request_buffering), NULL },
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
