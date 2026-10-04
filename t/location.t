use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
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
--- config
    location =/ {
        add_header message-primary $pq_message_primary always;
        add_header severity $pq_severity always;
        add_header severity-nonlocalized $pq_severity_nonlocalized always;
        add_header source-file $pq_source_file always;
        add_header source-function $pq_source_function always;
        add_header sqlstate $pq_sqlstate always;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1/0";
    }
--- request
GET /
--- error_code: 502
--- response_headers
Content-Type: text/html
message-primary: division by zero
severity: ERROR
severity-nonlocalized: ERROR
source-file: int.c
source-function: int4div
sqlstate: 22012
--- timeout: 60

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, $2 as cde" $arg_a::23 $arg_b::23 output=plain;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab union select $2 order by 1" $arg_a::23 $arg_b::23 output=plain;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, $2 as cde union select $3, $4 order by 1" $arg_a::23 $arg_b::23 $arg_c::23 $arg_d::23 output=plain;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select null::text as ab, $1 as cde union select $2, $3 order by 2" $arg_a::23 $arg_b $arg_c::23 output=plain;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, null::text as cde union select $2, $3 order by 1" $arg_a::23 $arg_b::23 $arg_c output=plain;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, $2 as cde union select $3, null::text order by 1" $arg_a::23 $arg_b $arg_c::23 output=plain;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, $2 as cde" $arg_a::23 $arg_b::23 output=csv;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab union select $2 order by 1" $arg_a::23 $arg_b::23 output=csv;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, $2 as cde union select $3, $4 order by 1" $arg_a::23 $arg_b::23 $arg_c::23 $arg_d::23 output=csv;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select null::text as ab, $1 as cde union select $2, $3 order by 2" $arg_a::23 $arg_b $arg_c::23 output=csv;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, null::text as cde union select $2, $3 order by 1" $arg_a::23 $arg_b::23 $arg_c output=csv;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1 as ab, $2 as cde union select $3, null::text order by 1" $arg_a::23 $arg_b $arg_c::23 output=csv;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
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
--- config
    location =/ {
        pq_empty 404;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1 where false";
    }
--- request
GET /
--- error_code: 404
--- timeout: 60

=== TEST 18:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        add_header my-var $myvar always;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 42" output=$myvar;
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

=== TEST 19:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        add_header my-var $myvar always;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 34 as ab, 'qwe' as cde" output=$myvar delimiter=,;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 1
Content-Type: text/plain
my-var: 34,qwe
--- response_body chomp
1
--- timeout: 60

=== TEST 20:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_empty 404;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1 where false";
        pq_query "select 42" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_body chomp
42
--- timeout: 60

=== TEST 21:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select repeat('a', 200000)" output=value string=on quote=" escape=";
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 200002
--- timeout: 5

=== TEST 22:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1/0";
    }
--- request
GET /
--- error_code: 502
--- error_log
PGRES_FATAL_ERROR
ERROR:  division by zero
--- timeout: 60

=== TEST 23:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "do $$ begin raise notice 'hello from doblock'; end $$";
    }
--- request
GET /
--- error_code: 200
--- error_log
NOTICE:  hello from doblock
--- timeout: 60

=== TEST 24:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1 as $arg_a$arg_b" output=value;
    }
--- request
GET /?a=foo&b=bar
--- error_code: 200
--- response_body chomp
1
--- timeout: 60

=== TEST 25:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "do $plpgsql$ begin raise notice 'hello from tagged doblock'; end $plpgsql$";
    }
--- request
GET /
--- error_code: 200
--- error_log
NOTICE:  hello from tagged doblock
--- timeout: 60

=== TEST 26:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_pass_request_body on;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select length($1)" $request_body output=value;
    }
--- request eval
"POST /\nab\x{00}cd"
--- error_code: 502
--- error_log
invalid byte sequence for encoding "UTF8": 0x00
--- timeout: 60

=== TEST 27:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1" delimiter=;
    }
--- request
GET /
--- must_die
--- error_log
empty "delimiter" value

=== TEST 28:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        default_type text/plain;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "copy (select i from generate_series(1, 100000) i) to stdout" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 588895
Content-Type: text/plain
--- response_body eval
CORE::join("", map { "$_\x{0a}" } 1..100000)
--- timeout: 10

=== TEST 29:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        default_type text/plain;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select i from generate_series(1, 100000) i" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 588894
Content-Type: text/plain
--- response_body eval
CORE::join("\x{0a}", 1..100000)
--- timeout: 10

=== TEST 30:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        mirror /fast;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select repeat('x', 100000) union all select pg_sleep(2)::text";
    }
    location =/fast {
        internal;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select pg_sleep(0.5)";
    }
--- request
GET /
--- error_code: 200
--- grep_error_log eval
qr/PGRES_TUPLES_OK and SELECT \d+/
--- grep_error_log_out
PGRES_TUPLES_OK and SELECT 1
PGRES_TUPLES_OK and SELECT 2
--- timeout: 10

=== TEST 31:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "do $$ begin raise notice 'stale notice'; end $$";
        pq_query "select 1/0";
    }
--- log_level: error
--- request
GET /
--- error_code: 502
--- error_log eval
qr/PGRES_FATAL_ERROR.*, client: 127\.0\.0\.1, server: localhost, request: "GET \/ HTTP\/1\.1"/
--- no_error_log
stale notice
[alert]
--- timeout: 10

=== TEST 32:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select pg_sleep(5)";
    }
--- request
GET /
--- abort
--- timeout: 0.5
--- wait: 1
--- ignore_response
--- error_log
canceling statement due to user request
--- no_error_log
[alert]


=== TEST 33:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "do $$ begin perform pg_sleep(2); exception when query_canceled then perform pg_terminate_backend(pg_backend_pid()); end $$";
    }
--- request
GET /
--- abort
--- timeout: 0.5
--- wait: 1
--- ignore_response
--- error_log
ngx_pq_drain_close
--- no_error_log
[alert]

=== TEST 34:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_body chomp
1
--- timeout: 10

=== TEST 35:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        set $pg nonexistent;
        pq_option user=postgres;
        pq_pass $pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 500
--- error_log
no port in upstream "nonexistent"
--- timeout: 10

=== TEST 36:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select $1::int + 1" $arg_a output=value;
    }
--- request
GET /?a=41
--- error_code: 200
--- response_body chomp
42
--- timeout: 10

=== TEST 37:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select count(*) from generate_series(1, 10) i where i < $1" $arg_a output=value;
    }
--- request
GET /?a=5
--- error_code: 200
--- response_body chomp
4
--- timeout: 10

=== TEST 38:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        default_type text/csv;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 'a,b' as x, 'say \"hi\"' as y, E'l1\\nl2' as z, '' as e, null::text as n" output=csv;
    }
--- request
GET /
--- error_code: 200
--- response_body eval
"x,y,z,e,n\x{0a}\"a,b\",\"say \"\"hi\"\"\",\"l1\x{0a}l2\",\"\","
--- timeout: 10
