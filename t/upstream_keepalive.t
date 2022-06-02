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
        pq_pass pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 1
Content-Type: text/plain
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
        pq_pass pg;
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
--- http_config
    upstream pg {
        keepalive 1;
        pq_option user=postgres;
        pq_prepare query "select $1 as ab, $2 as cde" 23 23;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_execute query $arg_a $arg_b output=plain;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 13
Content-Type: text/plain
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
        pq_execute query $arg_a $arg_b output=plain;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Content-Length: 9
Content-Type: text/plain
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
        pq_execute query $arg_a $arg_b $arg_c $arg_d output=plain;
        pq_pass pg;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
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
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        pq_pass pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
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
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        pq_pass pg;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
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
        pq_execute query $arg_a $arg_b $arg_c output=plain;
        pq_pass pg;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Content-Length: 19
Content-Type: text/plain
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
        pq_pass pg;
        pq_query "do $$ begin raise info '%', 1;end;$$";
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Length: 0
Content-Type: text/plain
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
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,\x{0a}"
--- timeout: 60
