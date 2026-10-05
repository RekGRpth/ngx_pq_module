# Nginx PostgreSQL upstream connection

Queries PostgreSQL from nginx through libpq, asynchronously (nonblocking, pipelined when a location or upstream has several queries), with keepalive of backend connections, query cancellation on client abort, streaming of large results and LISTEN/NOTIFY delivery to the push_stream module.

Requirements: libpq 14+ for several queries in one location or upstream (pipelining), libpq 17+ for chunkSize= and asynchronous query cancellation (older libpq cancels with the blocking PQcancel).

# Directives

pq_buffer_size
-------------
* Syntax: **pq_buffer_size** *size*
* Default: page size (usually 4k)
* Context: main, server, location, upstream

Sets the size the libpq input buffer of a cached (keepalive) connection is shrunk back to after a large result, so idle connections don't keep a large buffer each:
```nginx
upstream postgres {
    keepalive 8;
    pq_buffer_size 64k; # idle connections keep at most a 64k input buffer
}
```
pq_buffering
-------------
* Syntax: **pq_buffering** *on* | *off*
* Default: on
* Context: main, server, location

With on, the response is sent once all queries are done, with Content-Length, and an error at any point gives an error status (e.g. 502). With off, it is sent as the results come (chunked), which keeps memory low for large results (chunkSize=, COPY ... TO STDOUT): the status (200 or pq_empty) is sent with the first output, so an error after that cuts the response off instead, and pq_next_upstream doesn't retry; reading from the database pauses while the client can't take more:
```nginx
location =/postgres {
    pq_buffering off; # stream the result
    pq_pass postgres; # upstream is postgres
    pq_query "COPY (SELECT * FROM big) TO STDOUT" output=value; # sent as it comes
}
```
pq_empty
-------------
* Syntax: **pq_empty** *200* | *204* | *400* | *401* | *403* | *404* | *409*
* Default: 200
* Context: main, server, location, if in location

Sets HTTP status code for empty response. Status code will be set to given value only if all queries of the location return no rows (queries of the upstream don't count):
```nginx
location =/postgres {
    pq_empty 404; # returns 404 (not found), when 0 rows
    pq_query "SELECT 1 WHERE false"; # returns 0 rows
}
```
pq_execute
-------------
* Syntax: **pq_execute** *$query_name* [ *$argument_value* ] [ output=*csv* | output=*plain* | output=*value* | output=*binary* | output=*$variable* ] [ *output options* ]
* Default: --
* Context: location, if in location, upstream

Sets $query_name (nginx variables allowed), optional (several) $argument_value (nginx variables allowed) and output csv/plain/value/binary (location only, no nginx variables allowed, see Output) or $variable (create nginx variable, allowed in location and upstream) for execute:
```nginx
location =/postgres {
    pq_execute $query string $argument output=plain; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and plain output type
    pq_execute $query string $argument output=value; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and value output type
    pq_execute $query string $argument output=$variable; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and output to $variable variable
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_pass postgres; # upstream is postgres
}
# or
upstream postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_execute $query string $argument output=$variable; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and output to $variable variable
    pq_execute $query string $argument; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable)
    server postgres:5432; # host is postgres and port is 5432
}
```
Note: in location, output=$variable is populated per request, same as location queries in general. In upstream, output=$variable is populated once when a new backend connection is established (it runs before the location's own queries) and keeps its value for every subsequent request that reuses that connection (e.g. with keepalive) until the connection is closed.

Arguments are sent as text, the server infers their types (see pq_prepare for setting them). An argument containing a NUL byte, which no text value may hold, is rejected with 400.
pq_ignore_client_abort
-------------
* Syntax: **pq_ignore_client_abort** *on* | *off*
* Default: off
* Context: main, server, location

Determines whether the queries should keep running when the client closes the connection without waiting for the response. With off they are cancelled on the server:
```nginx
location =/postgres {
    pq_ignore_client_abort on; # finish the queries even if the client is gone
    pq_pass postgres; # upstream is postgres
    pq_query "CALL long_maintenance()";
}
```
pq_level
-------------
* Syntax: **pq_level** *level* "*message*"
* Default: --
* Context: upstream

Sets logging level for connection error:
```nginx
upstream postgres {
    pq_level info "session is read-only\n";
}
```
pq_log
-------------
* Syntax: **pq_log** *file* [ *level* ]
* Default: error_log logs/error.log error;
* Context: upstream

Sets logging for backend connections outliving their request (cached by keepalive, or finishing a cancelled query):
```nginx
upstream postgres {
    keepalive 8;
    pq_log /var/log/nginx/pg.err info; # set log level
}
```
pq_next_upstream
-------------
* Syntax: **pq_next_upstream** *error* | *timeout* | *non_idempotent* | *off* ...
* Default: error timeout
* Context: main, server, location

Specifies in which cases a request should be passed to the next server of the upstream, like proxy_next_upstream: *error* is an error connecting to the server or sending the queries, *timeout* is a timeout connecting (pq_option connect_timeout=). An error returned by a query itself (e.g. a constraint violation) is answered with 502 and not retried. Once a response has begun (pq_buffering off), there is no retry.
pq_next_upstream_timeout
-------------
* Syntax: **pq_next_upstream_timeout** *time*
* Default: 0
* Context: main, server, location

Limits the time during which a request can be passed to the next server, like proxy_next_upstream_timeout. 0 turns the limitation off.
pq_next_upstream_tries
-------------
* Syntax: **pq_next_upstream_tries** *number*
* Default: 0
* Context: main, server, location

Limits the number of possible tries for passing a request to the next server, like proxy_next_upstream_tries. 0 turns the limitation off.
pq_option
-------------
* Syntax: **pq_option** *name*=*value* ...
* Default: --
* Context: location, if in location, upstream

Sets libpq connection options with name (no nginx variables allowed) and value (no nginx variables allowed). Values may contain spaces, quotes and backslashes as is (e.g. "options=-c statement_timeout=5s"): they are quoted for libpq by the module. The options are checked when the configuration is loaded, so a mistake fails nginx -t with libpq's message. host, hostaddr and port are not allowed (they come from pq_pass or the upstream's server). Without pq_option libpq's defaults and environment apply (PGUSER, PGDATABASE, a service file etc.). application_name defaults to nginx. Options handled by the module itself:
* connect_timeout=*time* - limits connecting (nginx time syntax, default 60s, 0 means no limit, as in libpq); the queries themselves have no time limit (use statement_timeout for that);
* errors=*default* | *terse* | *verbose* | *sqlstate* - verbosity of error messages in the log;
* show_context=*errors* | *always* | *never* - when error messages in the log include the CONTEXT field.
```nginx
upstream postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    server unix:/run/postgresql:5432; # unix socket is in /run/postgresql directory and port is 5432
}
# or
location =/postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_pass postgres:5432; # host is postgres and port is 5432
}
# or
location =/postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_pass unix:/run/postgresql:5432; # unix socket is in /run/postgresql directory and port is 5432
}
# or
location =/postgres {
    pq_option user=user "options=-c statement_timeout=5s" connect_timeout=2s; # a session option with spaces, connect within 2 seconds
    pq_pass unix:/run/postgresql; # unix socket is in /run/postgresql directory and port is libpq default (5432)
}
```
In upstream also may use nginx keepalive module (before or after pq_option); the connections are then reused by later requests, along with their session state (prepared statements, LISTEN, SET):
```nginx
upstream postgres {
    keepalive 8;
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream postgres {
    keepalive 8;
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    server unix:/run/postgresql:5432; # unix socket is in /run/postgresql directory and port is 5432
}
```
pq_prepare
-------------
* Syntax: **pq_prepare** *$query_name* *sql* [ *$argument_oid* ]
* Default: --
* Context: location, if in location, upstream

Sets $query_name (nginx variables allowed), sql (named only nginx variables allowed as identifier only) and optional (several) $argument_oid (nginx variables allowed) for prepare. A statement is prepared once per backend connection: on a connection reused by keepalive the module remembers it and doesn't prepare it again (if it was dropped meanwhile, e.g. by DISCARD ALL, the request gets 502 and the next one prepares it again):
```nginx
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_prepare $query "SELECT $1, $2::text" 25 ""; # prepare query with name $query and two arguments (first query argument oid is 25 (TEXTOID) and second query argument is auto oid)
}
# or
upstream postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_prepare $query "SELECT $1, $2::text" 25 ""; # prepare query with name $query and two arguments (first query argument oid is 25 (TEXTOID) and second query argument is auto oid)
    server postgres:5432; # host is postgres and port is 5432
}
```
pq_pass
-------------
* Syntax: **pq_pass** *host*:*port* | unix:/*socket*[:*port*] | *$upstream*
* Default: --
* Context: location, if in location

Sets host (no nginx variables allowed) and port (no nginx variables allowed) or unix socket (no nginx variables allowed) and optional port (no nginx variables allowed, libpq default port if omitted) or upstream (nginx variables allowed):
```nginx
location =/postgres {
    pq_pass postgres:5432; # host is postgres and port is 5432
}
# or
location =/postgres {
    pq_pass unix:/run/postgresql:5432; # unix socket is in /run/postgresql directory and port is 5432
}
# or
location =/postgres {
    pq_pass unix:/run/postgresql; # unix socket is in /run/postgresql directory and port is libpq default (5432)
}
# or
location =/postgres {
    pq_pass postgres; # upstream is postgres
}
# or
location =/postgres {
    pq_pass $postgres; # upstream is taken from $postgres variable
}
```
pq_pass_request_body
-------------
* Syntax: **pq_pass_request_body** *on* | *off*
* Default: off
* Context: main, server, location

Enables reading the client request body, so queries can take it as an argument via the $request_body variable. The whole body is kept in memory: one larger than client_body_buffer_size is buffered to a temporary file by nginx and read back into memory when some query of the location (or of its upstream) refers to $request_body, so keep client_max_body_size reasonable:
```nginx
location =/postgres {
    client_max_body_size 1m; # the body, up to 1m, is held in memory
    pq_pass_request_body on; # read the request body
    pq_pass postgres; # upstream is postgres
    pq_query "insert into t (body) values ($1)" $request_body; # the body as an argument
}
```
pq_query
-------------
* Syntax: **pq_query** *sql* [ *$argument_value* | *$argument_value*::*$argument_oid* ] [ output=*csv* | output=*plain* | output=*value* | output=*binary* | output=*$variable* ] [ *output options* ]
* Default: --
* Context: location, if in location, upstream

Sets sql (named only nginx variables allowed as identifier only), optional (several) $argument_value (nginx variables allowed), $argument_oid (nginx variables allowed) and output csv/plain/value/binary (location only, no nginx variables allowed, see Output) or $variable (create nginx variable, allowed in location and upstream) for prepare and execute. Arguments without an oid are sent as text and the server infers their types; an argument containing a NUL byte is rejected with 400. Several queries in one location or upstream are sent together in a pipeline (libpq 14+, otherwise such a configuration fails to load):
```nginx
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "SELECT now()" output=csv; # prepare and execute simple query and csv output type
}
# or
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "listen $channel"; # listen channel from variable $channel
}
# or
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "SELECT 1/0"; # simple query with error
}
# or
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "SELECT $1, $2::text" string::25 $arg output=plain; # prepare and execute extended query with two arguments (first argument is string and its oid is 25 (TEXTOID) and second argument is taken from $arg variable and auto oid) and plain output type
}
# or
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "SELECT now()" output=$variable; # prepare and execute simple query and output to $variable variable
}
# or
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "do $$ begin raise notice 'hello'; end $$"; # Postgres dollar-quoted body ($$...$$ or $tag$...$tag$) is passed through as-is and not scanned for nginx variables
}
```
# Output
-------------
The rows of the location's queries go to the response body (output=csv, plain, value or binary) or to an nginx variable (output=$variable); a query without output= produces none. Rows are separated by a newline. When several queries write to one body, a header line (csv, plain) starts on a new line, while value output of the next query follows right after the previous one.
* output=*csv* - CSV with a header line: a field is quoted when it contains the delimiter, the quote, the escape character, CR or LF, and an empty string is quoted ("") to tell it from NULL, which is an empty field, as COPY ... CSV does;
* output=*plain* - tab separated with a header line, NULL as \N, values escaped like COPY ... TO in text format (\\, \t, \n, \r, ...);
* output=*value* - the values as they are, columns joined without a delimiter (set one with delimiter=), no header;
* output=*binary* - a single value in PostgreSQL binary format (e.g. a bytea as its raw bytes); a result with more than one value is an error (502).

Output options (location only):
* delimiter=*c* - column delimiter, one character;
* quote=*c*, escape=*c* - quote and escape characters (csv: both ");
* null=*string* - representation of NULL;
* header=*on* | *off* - the header line with column names;
* string=*on* | *off* - quote every field (csv);
* chunkSize=*n* - receive the result in chunks of n rows (libpq 17+) instead of all at once; with pq_buffering off each chunk is sent to the client as it comes.
```nginx
location =/postgres {
    pq_buffering off; # send as it comes
    pq_pass postgres; # upstream is postgres
    pq_query "SELECT * FROM big" output=csv chunkSize=1000 null=NULL; # csv, 1000 rows at a time, NULL spelled out
}
```
# LISTEN/NOTIFY
-------------
Notifications a backend connection receives (for its LISTEN) are passed to the push_stream module, if it is loaded, as messages of the channel with the same name; a notification for a channel push_stream doesn't have makes the connection UNLISTEN it. The push_stream channels a connection listens to (pq_query "listen name" or "listen $variable") are deleted when the connection is closed, so listen on an upstream with keepalive, where the connection stays open between requests:
```nginx
upstream postgres {
    keepalive 1;
    pq_option user=user dbname=dbname;
    server postgres:5432;
}
location =/listen {
    pq_pass postgres;
    pq_query "listen $arg_channel"; # notifications of this channel go to the push_stream channel $arg_channel
}
```
# Embedded Variables
-------------
* Syntax: $pq_*name*

The connection variables (parameter statuses, ssl attributes, database, host, user, pid, transaction status) are empty once the backend connection is closed, e.g. in the log phase without keepalive; the error fields keep the last error of the request.
```nginx
location =/postgres {
    add_header application_name $pq_application_name always; # application_name parameter status
    add_header cipher $pq_cipher always; # cipher ssl attribute
    add_header client_encoding $pq_client_encoding always; # client_encoding parameter status
    add_header column_name $pq_column_name always; # column_name result error field
    add_header compression $pq_compression always; # compression ssl attribute
    add_header constraint_name $pq_constraint_name always; # constraint_name result error field
    add_header context $pq_context always; # context result error field
    add_header datatype_name $pq_datatype_name always; # datatype_name result error field
    add_header datestyle $pq_datestyle always; # datestyle parameter status
    add_header db $pq_db always; # database name
    add_header default_transaction_read_only $pq_default_transaction_read_only always; # default_transaction_read_only parameter status
    add_header host $pq_host always; # database host name
    add_header hostaddr $pq_hostaddr always; # database host address
    add_header in_hot_standby $pq_in_hot_standby always; # in_hot_standby parameter status
    add_header integer_datetimes $pq_integer_datetimes always; # integer_datetimes parameter status
    add_header internal_position $pq_internal_position always; # internal_position result error field
    add_header internal_query $pq_internal_query always; # internal_query result error field
    add_header intervalstyle $pq_intervalstyle always; # intervalstyle parameter status
    add_header is_superuser $pq_is_superuser always; # is_superuser parameter status
    add_header key_bits $pq_key_bits always; # key_bits ssl attribute
    add_header library $pq_library always; # library ssl attribute
    add_header message_detail $pq_message_detail always; # message_detail result error field
    add_header message_hint $pq_message_hint always; # message_hint result error field
    add_header message_primary $pq_message_primary always; # message_primary result error field
    add_header options $pq_options always; # options parameter status
    add_header pid $pq_pid always; # backend pid
    add_header port $pq_port always; # database port
    add_header protocol $pq_protocol always; # protocol parameter status
    add_header schema_name $pq_schema_name always; # schema_name result error field
    add_header server_encoding $pq_server_encoding always; # server_encoding parameter status
    add_header server_version $pq_server_version always; # server_version parameter status
    add_header session_authorization $pq_session_authorization always; # session_authorization parameter status
    add_header severity $pq_severity always; # severity result error field
    add_header severity_nonlocalized $pq_severity_nonlocalized always; # severity_nonlocalized result error field
    add_header source_file $pq_source_file always;# source_file result error field
    add_header source_function $pq_source_function always; # source_function result error field
    add_header source_line $pq_source_line always; # source_line result error field
    add_header sqlstate $pq_sqlstate always; # sqlstate result error field
    add_header standard_conforming_strings $pq_standard_conforming_strings always; # standard_conforming_strings parameter status
    add_header statement_position $pq_statement_position always; # statement_position result error field
    add_header table_name $pq_table_name always; # table_name result error field
    add_header timezone $pq_timezone always; # timezone parameter status
    add_header transaction_status $pq_transaction_status always; # transaction status
    add_header user $pq_user always; # database user
}
```
# Testing
-------------
The tests use Test::Nginx and a PostgreSQL server on the unix socket /run/postgresql:5432 with user postgres; nginx is taken from PATH and the module from /etc/nginx/modules. Tests needing ngx_http_echo_module, ngx_http_push_stream_module or ngx_stream_module are skipped when those aren't installed.
```sh
prove t/*.t                      # the test suite
t/asan.sh                        # the suite against the module built with AddressSanitizer
t/stress.py                      # parallel clients, client aborts and backends terminated, under AddressSanitizer
t/stress.py --reload 3           # ... with nginx reloaded every 3 seconds
t/stress.py --module ~/src/nginx/objs/ngx_pq_module.so --duration 300 --rss 30 --no-kill # watch the workers' memory
```
t/asan.sh and t/stress.py build the module from the configured nginx source tree in $NGINX_SRC (default ~/src/nginx).
