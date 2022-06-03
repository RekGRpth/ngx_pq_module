use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_pass pg;
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
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body chomp
1
--- timeout: 60

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header message-primary $pq_message_primary always;
        add_header severity $pq_severity always;
        add_header severity-nonlocalized $pq_severity_nonlocalized always;
        add_header source-file $pq_source_file always;
        add_header source-function $pq_source_function always;
        add_header sqlstate $pq_sqlstate always;
        pq_pass pg;
        pq_query "select 1/0";
    }
--- request
GET /
--- error_code: 502
--- response_headers
Content-Length: 157
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
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_execute query $arg_a $arg_b output=plain;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 13
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345"
--- timeout: 60

=== TEST 4:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab union select $2 order by 1" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_execute query $arg_a $arg_b output=plain;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 9
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 5:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, $4 order by 1" 23 23 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_execute query $arg_a $arg_b $arg_c $arg_d output=plain;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345\x{0a}67\x{09}89"
--- timeout: 60

=== TEST 6:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select null::text as ab, $1 as cde union select $2, $3 order by 2" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        pq_pass pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}\\N\x{09}34\x{0a}qwe\x{09}89"
--- timeout: 60

=== TEST 7:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, null::text as cde union select $2, $3 order by 1" 23 23 "";
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        pq_pass pg;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}\\N\x{0a}89\x{09}qwe"
--- timeout: 60

=== TEST 8:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, null::text order by 1" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        pq_pass pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}qwe\x{0a}89\x{09}\\N"
--- timeout: 60

=== TEST 9:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b output=csv;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 13
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}12,345"
--- timeout: 60

=== TEST 10:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab union select $2 order by 1" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b output=csv;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 9
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 11:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, $4 order by 1" 23 23 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c $arg_d output=csv;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}12,345\x{0a}67,89"
--- timeout: 60

=== TEST 12:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select null::text as ab, $1 as cde union select $2, $3 order by 2" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c output=csv;
        pq_pass pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 17
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a},34\x{0a}qwe,89"
--- timeout: 60

=== TEST 13:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, null::text as cde union select $2, $3 order by 1" 23 23 "";
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c output=csv;
        pq_pass pg;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Content-Length: 17
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,\x{0a}89,qwe"
--- timeout: 60

=== TEST 14:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde union select $3, null::text order by 1" 23 "" 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_execute query $arg_a $arg_b $arg_c output=csv;
        pq_pass pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 17
Content-Type: text/csv
application-name: nginx
client-encoding: UTF8
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,"
--- timeout: 60

=== TEST 15:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        pq_pass pg;
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
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- timeout: 60

=== TEST 16:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    variables_hash_bucket_size 128;
    upstream pg {
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        add_header application-name $pq_application_name always;
        add_header client-encoding $pq_client_encoding always;
        add_header integer-datetimes $pq_integer_datetimes always;
        add_header intervalstyle $pq_intervalstyle always;
        add_header is-superuser $pq_is_superuser always;
        add_header server-encoding $pq_server_encoding always;
        add_header session-authorization $pq_session_authorization always;
        add_header standard-conforming-strings $pq_standard_conforming_strings always;
        default_type text/csv;
        pq_pass pg;
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
integer-datetimes: on
intervalstyle: postgres
is-superuser: on
server-encoding: UTF8
session-authorization: postgres
standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,\x{0a}"
--- timeout: 60
