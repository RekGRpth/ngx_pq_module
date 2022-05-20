#include <ngx_http.h>
#include <libpq-fe.h>

#define DEF_PGPORT 5432

ngx_module_t ngx_pq_module;

enum {
    ngx_pq_type_execute = 1 << 0,
    ngx_pq_type_function = 1 << 1,
    ngx_pq_type_location = 1 << 2,
    ngx_pq_type_output = 1 << 3,
    ngx_pq_type_prepare = 1 << 4,
    ngx_pq_type_query = 1 << 5,
    ngx_pq_type_upstream = 1 << 6,
};

typedef enum {
    ngx_pq_output_type_csv = 2,
    ngx_pq_output_type_none = 0,
    ngx_pq_output_type_plain = 3,
    ngx_pq_output_type_value = 1,
} ngx_pq_output_type_t;

typedef struct {
    struct {
        ngx_int_t index;
        uint32_t value;
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
    const char *client_encoding;
    const char **keywords;
    const char **values;
    ngx_msec_t timeout;
    ngx_url_t url;
    PGVerbosity verbosity;
} ngx_pq_connect_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
    ngx_pq_connect_t connect;
} ngx_pq_loc_conf_t;

typedef struct {
    ngx_flag_t header;
    ngx_flag_t string;
    ngx_int_t index;
    ngx_pq_output_type_t type;
    ngx_str_t null;
    u_char delimiter;
    u_char escape;
    u_char quote;
} ngx_pq_output_t;

typedef struct {
    ngx_array_t arguments;
    ngx_array_t commands;
    ngx_pq_output_t output;
    ngx_uint_t type;
    struct {
        ngx_int_t index;
        uint32_t oid;
    } function;
    struct {
        ngx_int_t index;
        ngx_str_t str;
    } name;
} ngx_pq_query_t;

typedef struct {
    ngx_array_t connects;
    ngx_array_t queries;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
} ngx_pq_srv_conf_t;

typedef struct ngx_pq_data_t ngx_pq_data_t;
typedef struct {
    ngx_array_t channels;
    ngx_array_t variables;
    ngx_connection_t *connection;
    ngx_msec_t timeout;
    ngx_pq_data_t *data;
    ngx_uint_t rc;
    struct {
        ngx_event_handler_pt read_handler;
        ngx_event_handler_pt write_handler;
        void *data;
    } keep;
    PGconn *conn;
    PGresult *result;
} ngx_pq_save_t;

typedef struct ngx_pq_data_t {
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_pq_loc_conf_t *plcf;
    ngx_pq_query_t *query;
    ngx_pq_save_t *save;
    ngx_pq_srv_conf_t *pscf;
    ngx_queue_t queue;
    ngx_uint_t col;
    ngx_uint_t row;
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
                query->output.type = ngx_pq_output_type_value;
                continue;
            }
            if (!(cmd->offset & ngx_pq_type_output)) return "output not allowed";
            ngx_uint_t j;
            if (cmd->offset & ngx_pq_type_function) {
                static const ngx_conf_enum_t e[] = { { ngx_string("value"), ngx_pq_output_type_value }, { ngx_null_string, 0 } };
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
                if (!e[j].name.len) return "\"output\" value must be \"value\"";
                query->output.type = e[j].value;
            } else {
                static const ngx_conf_enum_t e[] = { { ngx_string("csv"), ngx_pq_output_type_csv }, { ngx_string("plain"), ngx_pq_output_type_plain }, { ngx_string("value"), ngx_pq_output_type_value }, { ngx_null_string, 0 } };
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
                if (!e[j].name.len) return "\"output\" value must be \"csv\", \"plain\" or \"value\"";
                query->output.type = e[j].value;
            }
            switch (query->output.type) {
                case ngx_pq_output_type_csv: {
                    ngx_str_set(&query->output.null, "");
                    query->output.delimiter = ',';
                    query->output.escape = '"';
                    query->output.header = 1;
                    query->output.quote = '"';
                } break;
                case ngx_pq_output_type_plain: {
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
        if (cmd->offset & ngx_pq_type_query || cmd->offset & ngx_pq_type_function) {
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

static char *ngx_pq_pass_loc_server_ups_conf(ngx_conf_t *cf, ngx_pq_connect_t *connect, ngx_http_upstream_server_t *us) {
    ngx_str_t *args = cf->args->elts;
    ngx_str_t conninfo = ngx_null_string;
    static const ngx_conf_enum_t e[] = {
        { ngx_string("default"), PQERRORS_DEFAULT },
        { ngx_string("sqlstate"), PQERRORS_SQLSTATE },
        { ngx_string("terse"), PQERRORS_TERSE },
        { ngx_string("verbose"), PQERRORS_VERBOSE },
        { ngx_null_string, 0 }
    };
    connect->verbosity = PQERRORS_DEFAULT;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (us) {
            if (args[i].len > sizeof("weight=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("weight=") - 1),
                    .data = &args[i].data[sizeof("weight=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) return "\"weight\" value must be number";
                if (n <= 0) return "\"weight\" value must be positive";
                us->weight = (ngx_uint_t)n;
                continue;
            }
            if (args[i].len > sizeof("max_conns=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("max_conns=") - 1),
                    .data = &args[i].data[sizeof("max_conns=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) return "\"max_conns\" value must be number";
                us->max_conns = (ngx_uint_t)n;
                continue;
            }
            if (args[i].len > sizeof("max_fails=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("max_fails=") - 1),
                    .data = &args[i].data[sizeof("max_fails=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) return "\"max_fails\" value must be number";
                us->max_fails = (ngx_uint_t)n;
                continue;
            }
            if (args[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("fail_timeout=") - 1),
                    .data = &args[i].data[sizeof("fail_timeout=") - 1],
                };
                ngx_int_t n = ngx_parse_time(&str, 1);
                if (n == NGX_ERROR) return "\"fail_timeout\" value must be time";
                us->fail_timeout = (time_t)n;
                continue;
            }
            if (args[i].len == sizeof("backup") - 1 && !ngx_strncmp(args[i].data, (u_char *)"backup", sizeof("backup") - 1)) {
                us->backup = 1;
                continue;
            }
            if (args[i].len == sizeof("down") - 1 && !ngx_strncmp(args[i].data, (u_char *)"down", sizeof("down") - 1)) {
                us->down = 1;
                continue;
            }
        }
        if (args[i].len > sizeof("error_verbosity=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"error_verbosity=", sizeof("error_verbosity=") - 1)) {
            ngx_str_t str = {
                .len = args[i].len - (sizeof("error_verbosity=") - 1),
                .data = &args[i].data[sizeof("error_verbosity=") - 1],
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str.len && !ngx_strncmp(e[j].name.data, str.data, str.len)) break;
            if (!e[j].name.len) return "\"error_verbosity\" value must be \"default\", \"sqlstate\", \"terse\" or \"verbose\"";
            connect->verbosity = e[j].value;
            continue;
        }
        if (i > 1) conninfo.len++;
        conninfo.len += args[i].len;
    }
    if (!(conninfo.data = ngx_pnalloc(cf->pool, conninfo.len + 1))) return "!ngx_pnalloc";
    u_char *p = conninfo.data;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (us) {
            if (args[i].len > sizeof("weight=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) continue;
            if (args[i].len > sizeof("max_conns=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) continue;
            if (args[i].len > sizeof("max_fails=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) continue;
            if (args[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) continue;
            if (args[i].len == sizeof("backup") - 1 && !ngx_strncmp(args[i].data, (u_char *)"backup", sizeof("backup") - 1)) continue;
            if (args[i].len == sizeof("down") - 1 && !ngx_strncmp(args[i].data, (u_char *)"down", sizeof("down") - 1)) continue;
        }
        if (args[i].len > sizeof("error_verbosity=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"error_verbosity=", sizeof("error_verbosity=") - 1)) continue;
        if (i > 1) *p++ = ' ';
        p = ngx_copy(p, args[i].data, args[i].len);
    }
    *p = '\0';
    char *err;
    PQconninfoOption *opts = PQconninfoParse((const char *)conninfo.data, &err);
    if (!opts) {
        size_t len;
        if (err && (len = ngx_strlen(err))) {
            err[len - 1] = '\0';
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err);
            PQfreemem(err);
            return NGX_CONF_ERROR;
        }
        return "!PQconninfoParse";
    }
    u_char *connect_timeout = NULL;
    u_char *hostaddr = NULL;
    u_char *host = NULL;
    u_char *port = NULL;
    int arg = 0; // hostaddr or host
    arg++; // connect_timeout
    arg++; // fallback_application_name
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"connect_timeout")) { connect_timeout = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name")) continue; // !!! discard any fallback_application_name !!!
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"hostaddr")) { hostaddr = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"host")) { host = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"port")) port = (u_char *)opt->val; // !!! not continue !!!
        arg++;
    }
    arg++; // last
    if (!connect_timeout) connect->timeout = 60000; else {
        ngx_int_t n = ngx_parse_time(&(ngx_str_t){ngx_strlen(connect_timeout), connect_timeout}, 0);
        if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_parse_time == NGX_ERROR"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        connect->timeout = (ngx_msec_t)n;
    }
    if (hostaddr) {
        connect->url.url.len = ngx_strlen(hostaddr);
        if (!(connect->url.url.data = ngx_pnalloc(cf->pool, connect->url.url.len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn(connect->url.url.data, hostaddr, connect->url.url.len + 1);
    } else if (host) {
        connect->url.url.len = ngx_strlen(host);
        if (!(connect->url.url.data = ngx_pnalloc(cf->pool, connect->url.url.len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn(connect->url.url.data, host, connect->url.url.len + 1);
    } else {
        ngx_str_set(&connect->url.url, "unix:///run/postgresql");
        host = connect->url.url.data;
    }
    if (!port) connect->url.default_port = DEF_PGPORT; else {
        ngx_int_t n = ngx_atoi(port, ngx_strlen(port));
        if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_atoi == NGX_ERROR"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        connect->url.default_port = (in_port_t)n;
    }
    if (ngx_parse_url(cf->pool, &connect->url) != NGX_OK) {
        if (connect->url.err) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_parse_url(%V:%i) != NGX_OK and %s", &connect->url.url, connect->url.default_port, connect->url.err); }
        else { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_parse_url(%V:%i) != NGX_OK", &connect->url.url, connect->url.default_port); }
        PQconninfoFree(opts);
        return NGX_CONF_ERROR;
    }
    if (us) {
        us->addrs = connect->url.addrs;
        us->naddrs = connect->url.naddrs;
        us->name = connect->url.url;
    }
    if (host && connect->url.family != AF_UNIX) arg++; // host
    arg++;
    if (!(connect->keywords = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
    if (!(connect->values = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
    arg = 0; // hostaddr or host
    connect->keywords[arg] = connect->url.family == AF_UNIX ? "host" : "hostaddr";
    connect->values[arg] = (const char *)(connect->url.family == AF_UNIX ? host : hostaddr);
    arg++; // connect_timeout
    connect->keywords[arg] = "connect_timeout";
    if (!connect_timeout) connect->values[arg] = "60"; else {
        size_t val_len = ngx_strlen(connect_timeout);
        if (!(connect->values[arg] = ngx_pnalloc(cf->pool, val_len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)connect->values[arg], (u_char *)connect_timeout, val_len + 1);
    }
    arg++; // fallback_application_name
    connect->keywords[arg] = "fallback_application_name";
    connect->values[arg] = "nginx";
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"connect_timeout")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"hostaddr")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"host") && connect->url.family == AF_UNIX) continue;
        arg++;
        size_t keyword_len = ngx_strlen(opt->keyword);
        if (!(connect->keywords[arg] = ngx_pnalloc(cf->pool, keyword_len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)connect->keywords[arg], (u_char *)opt->keyword, keyword_len + 1);
        size_t val_len = ngx_strlen(opt->val);
        if (!(connect->values[arg] = ngx_pnalloc(cf->pool, val_len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pnalloc"); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)connect->values[arg], (u_char *)opt->val, val_len + 1);
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"client_encoding")) connect->client_encoding = connect->values[arg];
    }
    arg++; // last
    connect->keywords[arg] = NULL;
    connect->values[arg] = NULL;
    PQconninfoFree(opts);
    ngx_pfree(cf->pool, conninfo.data);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_pq_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    ngx_pq_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    if (uscf->srv_conf) {
        ngx_pq_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pq_module);
        if (pscf->peer.init(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
        d->pscf = pscf;
    } else {
        if (ngx_http_upstream_init_round_robin_peer(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_init_round_robin_peer != NGX_OK"); return NGX_ERROR; }
    }
    ngx_queue_init(&d->queue);
    ngx_pq_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pq_module);
    d->plcf = plcf;
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
    u->keepalive = !u->headers_in.connection_close;
    if (!plcf->queries.nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!queries"); return NGX_ERROR; }
    return NGX_OK;
}

static ngx_int_t ngx_pq_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return NGX_OK;
}

static void ngx_pq_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
}

static ngx_int_t ngx_pq_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    r->state = 0;
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

static char *ngx_pq_pass_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream || plcf->complex.value.data) return "is duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pq_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_str_t *str = cf->args->elts;
    ngx_url_t url = {0};
    if (cf->args->nelts == 2) {
        if (ngx_http_script_variables_count(&str[1])) {
            ngx_http_compile_complex_value_t ccv = {cf, &str[1], &plcf->complex, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
            return NGX_CONF_OK;
        }
        url.no_resolve = 1;
        url.url = str[1];
    } else {
        if (ngx_pq_pass_loc_server_ups_conf(cf, &plcf->connect, NULL) == NGX_CONF_ERROR) return NGX_CONF_ERROR;
        url = plcf->connect.url;
    }
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

static char *ngx_pq_server_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pq_srv_conf_t *pscf = conf;
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (uscf->peer.init_upstream != ngx_pq_peer_init_upstream) {
        pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
        uscf->peer.init_upstream = ngx_pq_peer_init_upstream;
    }
    ngx_pq_connect_t *connect;
    if (!pscf->connects.nelts && ngx_array_init(&pscf->connects, cf->pool, 1, sizeof(*connect)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(connect = ngx_array_push(&pscf->connects))) return "!ngx_array_push";
    ngx_memzero(connect, sizeof(*connect));
    ngx_http_upstream_server_t *us;
    if (!(us = ngx_array_push(uscf->servers))) return "!ngx_array_push";
    ngx_memzero(us, sizeof(*us));
    us->fail_timeout = 10;
    us->max_fails = 1;
    us->weight = 1;
    return ngx_pq_pass_loc_server_ups_conf(cf, connect, us);
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
  { ngx_string("pq_pass"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_pass_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pq_prepare"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_prepare_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_prepare, NULL },
  { ngx_string("pq_prepare"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_prepare_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_prepare, NULL },
  { ngx_string("pq_query"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pq_query_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pq_type_location|ngx_pq_type_query|ngx_pq_type_output, NULL },
  { ngx_string("pq_query"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_query_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pq_type_upstream|ngx_pq_type_query, NULL },
  { ngx_string("pq_server"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pq_server_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
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
