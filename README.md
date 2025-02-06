# Nginx PostgreSQL upstream connection

# Directives

pq_execute
-------------
* Syntax: **pq_execute** *$query_name* [ *$argument_value* ] [ output=*csv* | output=*plain* | output=*value* | output=*$variable* ]
* Default: --
* Context: location, if in location, upstream

Sets $query_name (nginx variables allowed), optional (several) $argument_value (nginx variables allowed) and output csv/plain/value (location only, no nginx variables allowed) or $variable (create nginx variable) for execute:
```nginx
location =/postgres {
    pq_execute $query string $argument output=plain; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and plain output type
    pq_execute $query string $argument output=value; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and value output type
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

Sets logging (used when keepalive):
```nginx
upstream postgres {
    keepalive 8;
    pq_log /var/log/nginx/pg.err info; # set log level
}
```
pq_option
-------------
* Syntax: **pq_option** *name*=*value*
* Default: --
* Context: location, if in location, upstream

Sets connection options with name (no nginx variables allowed) and value (no nginx variables allowed):
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
```
In upstream also may use nginx keepalive module:
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

Sets $query_name (nginx variables allowed), sql (named only nginx variables allowed as identifier only) and optional (several) $argument_oid (nginx variables allowed) for prepare:
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
* Syntax: **pq_pass** *host*:*port* | unix:/*socket*:*port* | *$upstream*
* Default: --
* Context: location, if in location

Sets host (no nginx variables allowed) and port (no nginx variables allowed) or unix socket (no nginx variables allowed) and port (no nginx variables allowed) or upstream (nginx variables allowed):
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
    pq_pass postgres; # upstream is postgres
}
# or
location =/postgres {
    pq_pass $postgres; # upstream is taken from $postgres variable
}
```
pq_empty
-------------
* Syntax: **pq_empty** *200* | *204* | *400* | *401* | *403* | *404*
* Default: 200
* Context: main, server, location, if in location

Sets HTTP status code for empty response. Status code will be set to given value only if all queries inside location returns nothing.
```nginx
location =/postgres {
    pq_empty 404; # returns 404 (not found), when 0 rows
    pq_query "SELECT 1 WHERE false"; # returns 0 rows
}
```
pq_query
-------------
* Syntax: **pq_query** *sql* [ *$argument_value* | *$argument_value*::*$argument_oid* ] [ output=*csv* | output=*plain* | output=*value* | output=*$variable* ]
* Default: --
* Context: location, if in location, upstream

Sets sql (named only nginx variables allowed as identifier only), optional (several) $argument_value (nginx variables allowed), $argument_oid (nginx variables allowed) and output csv/plain/value (location only, no nginx variables allowed) or $variable (create nginx variable) for prepare and execute:
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
```
# Embedded Variables
-------------
* Syntax: $pq_*name*

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
