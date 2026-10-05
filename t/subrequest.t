use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        auth_request /auth;
        echo ok;
    }
    location =/auth {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1";
    }
--- request
GET /
--- response_body
ok
--- timeout: 10

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        auth_request /auth;
        echo ok;
    }
    location =/auth {
        pq_empty 403;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1 where false";
    }
--- request
GET /
--- error_code: 403
--- timeout: 10

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        auth_request /auth;
        auth_request_set $u $user;
        echo "user $u";
    }
    location =/auth {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 'bob'" output=$user;
    }
--- request
GET /
--- response_body
user bob
--- timeout: 10

=== TEST 4:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        default_type text/html;
        ssi on;
        echo -n 'a<!--# include virtual="/db" -->b';
    }
    location =/db {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- response_body: a1b
--- timeout: 10

=== TEST 5:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        default_type text/html;
        ssi on;
        echo -n 'a<!--# include virtual="/db" -->b';
    }
    location =/db {
        pq_buffering off;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "copy (select i from generate_series(1, 100000) i) to stdout" output=value;
    }
--- request
GET /
--- response_body eval
"a" . CORE::join("", map { "$_\x{0a}" } 1..100000) . "b"
--- timeout: 10

=== TEST 6:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        echo_location_async /slow;
        echo_location_async /fast;
        echo_location_async /big;
    }
    location =/slow {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 'slow' from pg_sleep(1)" output=value;
    }
    location =/fast {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 'fast'" output=value;
    }
    location =/big {
        pq_buffering off;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "copy (select i from generate_series(1, 50000) i) to stdout" output=value;
    }
--- request
GET /
--- response_body eval
"slowfast" . CORE::join("", map { "$_\x{0a}" } 1..50000)
--- timeout: 10

=== TEST 7:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        auth_request /auth;
        echo ok;
    }
    location =/auth {
        pq_buffering off;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- response_body
ok
--- timeout: 10

=== TEST 8:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        limit_rate 300k;
        default_type text/html;
        ssi on;
        echo -n 'a<!--# include virtual="/db" -->b';
    }
    location =/db {
        pq_buffering off;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "copy (select i from generate_series(1, 100000) i) to stdout" output=value;
    }
--- request
GET /
--- response_body eval
"a" . CORE::join("", map { "$_\x{0a}" } 1..100000) . "b"
--- timeout: 20

=== TEST 9:
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- config
    location =/ {
        limit_rate 300k;
        echo_location_async /slow;
        echo_location_async /big;
    }
    location =/slow {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select 'slow' from pg_sleep(1)" output=value;
    }
    location =/big {
        pq_buffering off;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "copy (select i from generate_series(1, 100000) i) to stdout" output=value;
    }
--- request
GET /
--- response_body eval
"slow" . CORE::join("", map { "$_\x{0a}" } 1..100000)
--- timeout: 20
