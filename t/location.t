use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body chomp
1
--- timeout: 60

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1/0";
    }
--- request
GET /
--- error_code: 502
--- response_headers
Content-Length: 157
Content-Type: text/html
--- timeout: 60

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345"
--- timeout: 60

=== TEST 4:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 5:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345\x{0a}67\x{09}89"
--- timeout: 60

=== TEST 6:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}\\N\x{09}34\x{0a}qwe\x{09}89"
--- timeout: 60

=== TEST 7:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}\\N\x{0a}89\x{09}qwe"
--- timeout: 60

=== TEST 8:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}qwe\x{0a}89\x{09}\\N"
--- timeout: 60

=== TEST 9:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}12,345"
--- timeout: 60

=== TEST 10:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 11:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}12,345\x{0a}67,89"
--- timeout: 60

=== TEST 12:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a},34\x{0a}qwe,89"
--- timeout: 60

=== TEST 13:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,\x{0a}89,qwe"
--- timeout: 60

=== TEST 14:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,"
--- timeout: 60

=== TEST 15:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- timeout: 60

=== TEST 16:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        add_header option-application-name $pq_option_application_name always;
        add_header option-client-encoding $pq_option_client_encoding always;
        add_header option-integer-datetimes $pq_option_integer_datetimes always;
        add_header option-intervalstyle $pq_option_intervalstyle always;
        add_header option-is-superuser $pq_option_is_superuser always;
        add_header option-server-encoding $pq_option_server_encoding always;
        add_header option-session-authorization $pq_option_session_authorization always;
        add_header option-standard-conforming-strings $pq_option_standard_conforming_strings always;
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
option-application-name: nginx
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,\x{0a}"
--- timeout: 60
