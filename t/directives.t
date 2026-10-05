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
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "create sequence if not exists pq_ignore_client_abort";
        pq_query "select setval('pq_ignore_client_abort', 1)";
    }
--- request
GET /
--- error_code: 200
--- timeout: 10

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_ignore_client_abort on;
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select setval('pq_ignore_client_abort', 42) from pg_sleep(1)";
    }
--- request
GET /
--- abort
--- timeout: 0.3
--- wait: 1.5
--- ignore_response

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select last_value from pq_ignore_client_abort" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_body chomp
42
--- timeout: 10

=== TEST 4:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select setval('pq_ignore_client_abort', 1)";
    }
--- request
GET /
--- error_code: 200
--- timeout: 10

=== TEST 5:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select setval('pq_ignore_client_abort', 42) from pg_sleep(1)";
    }
--- request
GET /
--- abort
--- timeout: 0.3
--- wait: 1.5
--- ignore_response

=== TEST 6:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
--- config
    location =/ {
        pq_option user=postgres;
        pq_pass unix:/run/postgresql:5432;
        pq_query "select last_value from pq_ignore_client_abort" output=value;
    }
--- request
GET /
--- error_code: 200
--- response_body chomp
1
--- timeout: 10

=== TEST 7:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        pq_option user=postgres;
        server 127.0.0.1:1;
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
--- response_body chomp
1
--- timeout: 10

=== TEST 8:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        pq_option user=postgres;
        server 127.0.0.1:1;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_next_upstream off;
        pq_pass pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 502
--- timeout: 10

=== TEST 9:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
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
--- grep_error_log eval
qr/division by zero/
--- grep_error_log_out
division by zero
--- timeout: 10

=== TEST 10:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        pq_option user=postgres connect_timeout=1s;
        server 127.0.0.1:1987;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_pass pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- tcp_listen: 1987
--- tcp_no_close
--- tcp_reply:
--- error_code: 200
--- response_body chomp
1
--- error_log
upstream timed out
--- timeout: 10

=== TEST 11:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        pq_option user=postgres;
        server 127.0.0.1:1;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_next_upstream_tries 1;
        pq_pass pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- error_code: 502
--- timeout: 10

=== TEST 12:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        pq_option user=postgres connect_timeout=1s;
        server 127.0.0.1:1987;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_next_upstream_timeout 500ms;
        pq_pass pg;
        pq_query "select 1" output=value;
    }
--- request
GET /
--- tcp_listen: 1987
--- tcp_no_close
--- tcp_reply:
--- error_code: 504
--- timeout: 10

=== TEST 13:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_buffer_size 4k;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_pass pg;
        pq_query "select repeat('x', 100000)" output=value;
    }
--- request
GET /
--- error_code: 200
--- error_log
inBufSize
--- timeout: 10

=== TEST 14:
--- main_config
    load_module /etc/nginx/modules/ngx_pq_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pq_buffer_size 1m;
        pq_option user=postgres;
        server unix:/run/postgresql:5432;
    }
--- config
    location =/ {
        pq_pass pg;
        pq_query "select repeat('x', 100000)" output=value;
    }
--- request
GET /
--- error_code: 200
--- no_error_log
inBufSize
--- timeout: 10
