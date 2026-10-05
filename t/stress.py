#!/usr/bin/env python3
"""Concurrency stress for ngx_pq_module.

Parallel clients hit keepalive, pipelined, chunked, streamed, COPY, slow and
LISTEN/NOTIFY locations; some abort mid-response; backends of nginx are
terminated with pg_terminate_backend every half a second. By default the
module is built with AddressSanitizer from the configured nginx tree, like
t/asan.sh does.

Usage: t/stress.py [--duration 120] [--clients 50] [--port 1990] [--no-asan] [--keep]
  NGINX_SRC  configured nginx source tree with this module (default: $HOME/src/nginx)

Fails on ASan reports, [alert]s, crashed workers, hung requests, wrong
response bodies, or backends left after nginx exits. 502s and streamed
responses cut off part way are expected: backends are killed meanwhile.
"""
import argparse, asyncio, glob, os, re, shutil, subprocess, sys, tempfile, time

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--duration', type=float, default=120)
parser.add_argument('--clients', type=int, default=50)
parser.add_argument('--port', type=int, default=1990)
parser.add_argument('--no-asan', action='store_true', help='use the installed /etc/nginx/modules/ngx_pq_module.so')
parser.add_argument('--keep', action='store_true', help='keep the temporary directory')
opt = parser.parse_args()

W = tempfile.mkdtemp(prefix='ngx_pq_stress.')
PORT = opt.port

def build_asan():
    nginx = os.environ.get('NGINX_SRC', os.path.expanduser('~/src/nginx'))
    makefile = open(os.path.join(nginx, 'objs/Makefile')).read()
    module = re.search(r'\S*ngx_pq_module\.c', makefile).group(0)
    cmds = subprocess.run(['make', '-n', '-W', module, '-f', 'objs/Makefile', 'objs/ngx_pq_module.so'],
                          cwd=nginx, capture_output=True, text=True, check=True).stdout
    cmds = re.sub(r'(?m)^cc -c ', 'cc -c -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer ', cmds)
    cmds = re.sub(r'(?m)^cc -o ', 'cc -fsanitize=address -o ', cmds)
    cmds = cmds.replace('objs/addon/ngx_pq_module/ngx_pq_module.o', f'{W}/ngx_pq_module.o').replace('objs/ngx_pq_module.so', f'{W}/ngx_pq_module.so')
    subprocess.run(['sh', '-e'], input=cmds, cwd=nginx, text=True, check=True, stdout=subprocess.DEVNULL)
    return f'{W}/ngx_pq_module.so'

SO = '/etc/nginx/modules/ngx_pq_module.so' if opt.no_asan else build_asan()
LIBASAN = None if opt.no_asan else subprocess.check_output(['cc', '-print-file-name=libasan.so'], text=True).strip()

CONF = f'''daemon off; master_process on; worker_processes 2;
error_log {W}/logs/error.log info; pid {W}/logs/nginx.pid;
load_module {SO};
events {{ worker_connections 1024; }}
http {{
    access_log off;
    client_body_temp_path {W}/tmp; proxy_temp_path {W}/tmp; fastcgi_temp_path {W}/tmp; uwsgi_temp_path {W}/tmp; scgi_temp_path {W}/tmp;
    upstream pg {{
        keepalive 8;
        pq_option user=postgres application_name=stress;
        server unix:/run/postgresql:5432;
    }}
    server {{
        listen 127.0.0.1:{PORT};
        location =/q {{ pq_pass pg; pq_query "select $1::int * 2" $arg_i output=value; }}
        location =/pipe {{ pq_pass pg; pq_query "select $1::int" $arg_i output=value; pq_query "select $1::int + 1" $arg_i output=value; }}
        location =/big {{ pq_pass pg; pq_query "copy (select i from generate_series(1, 20000) i) to stdout" output=value; }}
        location =/chunk {{ pq_pass pg; pq_query "select i from generate_series(1, $1::int) i" $arg_n output=value chunkSize=100; }}
        location =/stream {{ pq_buffering off; pq_pass pg; pq_query "copy (select i from generate_series(1, 50000) i) to stdout" output=value; }}
        location =/slow {{ pq_pass pg; pq_query "select $1::int from pg_sleep(random() * 0.3)" $arg_i output=value; }}
        location =/listen {{ pq_pass pg; pq_query "listen ch"; pq_query "notify ch, 'x'"; }}
        location =/direct {{ pq_option user=postgres application_name=stress; pq_pass unix:/run/postgresql:5432; pq_query "select $1::int * 2" $arg_i output=value; }}
        location =/kill {{ pq_option user=postgres application_name=killer; pq_pass unix:/run/postgresql:5432;
            pq_query "select count(pg_terminate_backend(pid)) from (select pid from pg_stat_activity where application_name = 'stress' order by random() limit 2) s" output=value; }}
    }}
}}
'''

def expected(path, args):
    if path in ('/q', '/direct'): return str(int(args['i']) * 2).encode()
    if path == '/pipe': return f"{args['i']}{int(args['i']) + 1}".encode()
    if path == '/big': return ''.join(f'{i}\n' for i in range(1, 20001)).encode()
    if path == '/stream': return ''.join(f'{i}\n' for i in range(1, 50001)).encode()
    if path == '/chunk': return '\n'.join(str(i) for i in range(1, int(args['n']) + 1)).encode()
    if path == '/slow': return args['i'].encode()
    return b''

stats, problems = {}, []
def count(k): stats[k] = stats.get(k, 0) + 1

async def one():
    import random
    path = random.choice(['/q', '/q', '/pipe', '/big', '/chunk', '/stream', '/slow', '/listen', '/direct'])
    args = {'i': str(random.randint(-1000, 1000)), 'n': str(random.randint(1, 3000))}
    qs = '&'.join(f'{k}={v}' for k, v in args.items())
    try:
        r, w = await asyncio.open_connection('127.0.0.1', PORT)
        w.write(f'GET {path}?{qs} HTTP/1.0\r\nHost: x\r\n\r\n'.encode()); await w.drain()
        if random.random() < 0.1:  # abort mid-response
            await asyncio.sleep(random.random() * 0.2)
            try: await asyncio.wait_for(r.read(random.randint(1, 50000)), 0.5)
            except asyncio.TimeoutError: pass
            w.close(); count('aborted'); return
        data = await asyncio.wait_for(r.read(-1), 30)
        w.close()
    except asyncio.TimeoutError:
        count(f'HUNG {path}'); problems.append(f'hung: {path}?{qs}'); return
    except Exception as ex:
        count(f'connection error {ex.__class__.__name__}'); return
    head, _, body = data.partition(b'\r\n\r\n')
    status = head.split(b' ', 2)[1].decode() if head.startswith(b'HTTP/') else 'none'
    if status != '200': count(f'{status} {path}'); return
    exp = expected(path, args)
    if body == exp: count('200 ok')
    elif path == '/stream' and exp.startswith(body) and (not body or body.endswith(b'\n')): count('200 cut off (streamed, backend killed)')
    else: count(f'WRONG BODY {path}'); problems.append(f'wrong body: {path}?{qs}: {body[:80]!r}... ({len(body)} bytes)')

async def client(stop):
    while time.time() < stop: await one()

async def killer(stop):
    while time.time() < stop:
        await asyncio.sleep(0.5)
        try:
            r, w = await asyncio.open_connection('127.0.0.1', PORT)
            w.write(b'GET /kill HTTP/1.0\r\nHost: x\r\n\r\n'); await w.drain(); await r.read(-1); w.close(); count('backends killed')
        except Exception: count('kill failed')

def stress_backends():
    try:
        return subprocess.check_output(['psql', '-U', 'postgres', '-h', '/run/postgresql', '-Atc',
            "select count(*) from pg_stat_activity where application_name = 'stress'"], text=True).strip()
    except Exception as ex:
        return f'? ({ex.__class__.__name__})'

async def main():
    for sub in ('logs', 'tmp'): os.makedirs(os.path.join(W, sub))
    open(os.path.join(W, 'nginx.conf'), 'w').write(CONF)
    env = dict(os.environ)
    if LIBASAN: env.update(LD_PRELOAD=LIBASAN, ASAN_OPTIONS=f'detect_leaks=0:halt_on_error=0:log_path={W}/asan')
    p = subprocess.Popen(['nginx', '-p', W, '-c', os.path.join(W, 'nginx.conf')], env=env)
    await asyncio.sleep(1.5)
    stop = time.time() + opt.duration
    await asyncio.gather(killer(stop), *[client(stop) for _ in range(opt.clients)])
    await asyncio.sleep(3)
    print('stress backends left idle after the load:', stress_backends())
    p.send_signal(3); p.wait(timeout=30)
    await asyncio.sleep(1)
    left = stress_backends()
    print('stress backends left after nginx exits:', left)
    for k, v in sorted(stats.items(), key=lambda kv: -kv[1]): print(f'{v:8} {k}')
    log = open(os.path.join(W, 'logs', 'error.log'), errors='replace').read()
    alerts = log.count('[alert]') + log.count('exited on signal')
    reports = glob.glob(os.path.join(W, 'asan.*'))
    print(f'alerts and crashed workers: {alerts}, AddressSanitizer reports: {len(reports)}')
    for line in problems[:20]: print(line)
    for f in reports: sys.stdout.write(open(f, errors='replace').read())
    return 1 if alerts or reports or problems or left not in ('0',) else 0

try:
    rc = asyncio.run(main())
finally:
    if opt.keep: print('kept in', W)
    else: shutil.rmtree(W, ignore_errors=True)
sys.exit(rc)
