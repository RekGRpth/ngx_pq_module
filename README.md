# Nginx PostgreSQL upstream connection

# Directives

pq_execute
-------------
* Syntax: **pq_execute** *$query_name* [ *$argument_value* ] [ output=*csv* | output=*plain* | output=*value* | output=*$variable* ]
* Default: --
* Context: location, if in location, upstream

Sets $query_name (nginx variables allowed), optional (several) $argument_value (nginx variables allowed) and output csv/plain/value (no nginx variables allowed) or $variable (create nginx variable) for execute:
```nginx
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_execute $query string $argument output=$variable; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and output to $variable variable
    pq_execute $query string $argument output=csv; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and csv output type
    pq_execute $query string $argument output=plain; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and plain output type
    pq_execute $query string $argument output=value; # execute query with name $query and two arguments (first argument is string and second argument is taken from $argument variable) and value output type
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
    server unix:/run/postgresql:5432; # unix socket connection and port is 5432
}
# or
location =/postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_pass postgres:5432; # host is postgres and port is 5432
}
# or
location =/postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_pass unix:/run/postgresql:5432; # unix socket connection
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
    server unix:/run/postgresql:5432; # unix socket connection
}
```
pq_prepare
-------------
* Syntax: **pq_prepare** *$query* *sql* [ *$oid* ]
* Default: --
* Context: location, if in location, upstream

Prepare query(queries) (nginx variables allowed) sql(s) (named only nginx variables allowed as identifier only), optional argument(s)'s oid(s) (nginx variables allowed):
```nginx
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_prepare $query "SELECT $1, $2::text" 25 ""; # parser query wich name is taken from $query variable and two arguments: first query argument oid is 25 (TEXTOID) and second query argument is auto oid
}
# or
upstream postgres {
    pq_option user=user dbname=dbname application_name=application_name; # set user, dbname and application_name
    pq_prepare $query "SELECT $1, $2::text" 25 ""; # parser query wich name is taken from $query variable and two arguments: first query argument oid is 25 (TEXTOID) and second query argument is auto oid
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
pq_query
-------------
* Syntax: **pq_query** *sql* [ *$arg* | *$arg*::*$oid* ] [ output=*csv* | output=*plain* | output=*value* | output=*$variable* ]
* Default: --
* Context: location, if in location, upstream

Sets query(queries) sql(s) (named only nginx variables allowed as identifier only), optional argument(s) (nginx variables allowed) and it(s) oid(s) (nginx variables allowed) and output type (no nginx variables allowed):
```nginx
location =/postgres {
    pq_pass postgres; # upstream is postgres
    pq_query "SELECT now()" output=csv; # simple query and csv output type
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
    pq_query "SELECT $1, $2::text" str::25 $arg output=plain; # extended query with two arguments: first query argument is str and its oid is 25 (TEXTOID) and second query argument is taken from $arg variable and auto oid and plain output type
}
```
