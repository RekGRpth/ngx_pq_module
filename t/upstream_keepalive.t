use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
repeat_each(2);
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        set $pg pg;
        pq_pass $pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 1
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body chomp
1
--- timeout: 60

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header message-primary $pq_message_primary always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header severity $pq_severity always;
        add_header severity-nonlocalized $pq_severity_nonlocalized always;
        add_header source-file $pq_source_file always;
        add_header source-function $pq_source_function always;
        add_header sqlstate $pq_sqlstate always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        set $pg pg;
        pq_pass $pg;
        pq_query "select 1/0";
    }
--- request
GET /
--- error_code: 502
--- response_headers
Content-Type: text/html
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
message-primary: division by zero
port: 5432
server-encoding: UTF8
session-authorization: postgres
severity: ERROR
severity-nonlocalized: ERROR
source-file: int.c
source-function: int4div
sqlstate: 22012
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- timeout: 60

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        pq_execute query $arg_a $arg_b output=plain;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 13
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345"
--- timeout: 60

=== TEST 4:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab union select $2 order by 1" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        pq_execute query $arg_a $arg_b output=plain;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 9
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 5:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, $4 order by 1" 23 23 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        pq_execute query $arg_a $arg_b $arg_c $arg_d output=plain;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345\x{0a}67\x{09}89"
--- timeout: 60

=== TEST 6:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select null::text as ab, $1 as cde union select $2, $3 order by 2" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{09}cde\x{0a}\\N\x{09}34\x{0a}qwe\x{09}89"
--- timeout: 60

=== TEST 7:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, null::text as cde union select $2, $3 order by 1" 23 23 "";
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}\\N\x{0a}89\x{09}qwe"
--- timeout: 60

=== TEST 8:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, null::text order by 1" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}qwe\x{0a}89\x{09}\\N"
--- timeout: 60

=== TEST 9:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b output=csv;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 13
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab,cde\x{0a}12,345"
--- timeout: 60

=== TEST 10:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab union select $2 order by 1" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b output=csv;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 9
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 11:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, $4 order by 1" 23 23 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c $arg_d output=csv;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab,cde\x{0a}12,345\x{0a}67,89"
--- timeout: 60

=== TEST 12:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select null::text as ab, $1 as cde union select $2, $3 order by 2" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c output=csv;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 17
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab,cde\x{0a},34\x{0a}qwe,89"
--- timeout: 60

=== TEST 13:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, null::text as cde union select $2, $3 order by 1" 23 23 "";
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c output=csv;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Content-Length: 17
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab,cde\x{0a}34,\x{0a}89,qwe"
--- timeout: 60

=== TEST 14:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, null::text order by 1" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c output=csv;
        set $pg pg;
        pq_pass $pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 17
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,"
--- timeout: 60

=== TEST 15:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        set $pg pg;
        pq_pass $pg;
        pq_query "do $$ begin raise info '%', 1;end;$$";
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 0
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- timeout: 60

=== TEST 16:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header db $pq_db always;
        add_header default-transaction-read-only $pq_default_transaction_read_only always;
        add_header host $pq_host always;
        add_header in-hot-standby $pq_in_hot_standby always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header port $pq_port always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        add_header transaction-status $pq_transaction_status always;
        add_header user $pq_user always;
        default_type text/csv;
        set $pg pg;
        pq_pass $pg;
        pq_query "copy (select 34 as ab, 'qwe' as cde union select 89, null order by 1) to stdout with (format csv, header true)" output=value;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 18
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
db: postgres
default-transaction-read-only: off
host: /run/postgresql
in-hot-standby: off
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
port: 5432
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
transaction-status: IDLE
user: postgres
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,\x{0a}"
--- timeout: 60

=== TEST 17:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_query "select 42" output=$myvar;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header my-var $myvar always;
        set $pg pg;
        pq_pass $pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 1
Content-Type: text/plain
my-var: 42
--- response_body chomp
1
--- timeout: 60

=== TEST 18:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_query "select 'ab' union select 'cd' order by 1" output=$myvar;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        set $pg pg;
        pq_pass $pg;
        pq_query "select length($1)" $myvar output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 1
Content-Type: text/plain
--- response_body chomp
5
--- timeout: 60

=== TEST 19:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        default_type text/plain;
        set $pg pg;
        pq_pass $pg;
        pq_query "copy (select i from generate_series(1, 100000) i) to stdout" output=value;
    }
--- request eval
["GET /", "GET /"]
--- error_code eval
[200, 200]
--- response_body eval
[CORE::join("", map { "$_\x{0a}" } 1..100000), CORE::join("", map { "$_\x{0a}" } 1..100000)]
--- timeout: 10

=== TEST 20:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        default_type text/plain;
        set $pg pg;
        pq_pass $pg;
        pq_query "select i from generate_series(1, 100000) i" output=value;
    }
--- request eval
["GET /", "GET /"]
--- error_code eval
[200, 200]
--- response_body eval
[CORE::join("\x{0a}", 1..100000), CORE::join("\x{0a}", 1..100000)]
--- timeout: 10

=== TEST 21:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        set $pg pg;
        pq_pass $pg;
        pq_prepare query "select $1 + 1" 23;
        pq_execute query $arg_a output=value;
    }
--- request eval
["GET /?a=1", "GET /?a=2"]
--- error_code eval
[200, 200]
--- response_body eval
["2", "3"]
--- timeout: 10

=== TEST 22:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        set $pg pg;
        pq_pass $pg;
        pq_prepare query "select $1 + 1" 23;
        pq_execute query $arg_a output=value;
    }
    location =/dealloc {
        set $pg pg;
        pq_pass $pg;
        pq_query "deallocate all";
    }
--- request eval
["GET /?a=1", "GET /dealloc", "GET /?a=2", "GET /?a=3"]
--- error_code eval
[200, 200, 502, 200]
--- response_body_like eval
["^2\$", "^\$", ".*", "^4\$"]
--- timeout: 10

=== TEST 23:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        set $pg pg;
        pq_pass $pg;
        pq_query "select set_config('my.n', (coalesce(nullif(current_setting('my.n', true), ''), '0')::int + 1)::text, false)" output=value;
    }
--- request eval
["GET /", "GET /"]
--- error_code eval
[200, 200]
--- response_body_like eval
["^\\d+\$", "^(?!1\$)\\d+\$"]
--- timeout: 10

=== TEST 24:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        set $pg pg;
        pq_pass $pg;
        pq_query "select 1" output=value;
    }
    location =/slow {
        set $pg pg;
        pq_pass $pg;
        pq_query "do $$ begin perform pg_sleep(2); exception when query_canceled then perform pg_sleep(2); end $$";
    }
--- request eval
["GET /", "GET /slow", "GET /"]
--- abort
--- timeout: 0.5
--- ignore_response
--- no_error_log
another command is already in progress

=== TEST 25:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres connect_timeout=1s;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        set $pg pg;
        pq_pass $pg;
        pq_query "select pg_sleep($1)" $arg_s::701 output=value;
    }
--- request eval
["GET /?s=0", "GET /?s=2"]
--- error_code eval
[200, 200]
--- timeout: 10

=== TEST 26:
--- skip_eval: 12: !-e "/etc/nginx/modules/ngx_http_push_stream_module.so"
--- main_config
    load_module /etc/nginx/modules/ngx_http_push_stream_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    push_stream_shared_memory_size 32m;
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/pub {
        push_stream_publisher admin;
        push_stream_channels_path $arg_id;
        push_stream_store_messages on;
    }
    location ~ ^/sub/(.*) {
        push_stream_subscriber polling;
        push_stream_channels_path $1;
        push_stream_message_template "~text~;";
    }
    location =/ {
        pq_pass pg;
        pq_query "listen ch";
        pq_query "notify ch, 'hello'";
    }
    location =/notify {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "notify ch, 'idle'";
    }
--- request eval
["DELETE /pub?id=ch", "POST /pub?id=ch\nfirst", "GET /", "GET /notify", "GET /pub?id=ch", "GET /sub/ch"]
--- more_headers eval
["", "", "", "", "", "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\nIf-None-Match: 0"]
--- error_code_like eval
["^(?:200|404)\$", "^200\$", "^200\$", "^200\$", "^200\$", "^200\$"]
--- response_body_like eval
[".*", '"published_messages": 1,', "^\$", "^\$", '"published_messages": 3,', "^first;hello;idle;\$"]
--- timeout: 10
