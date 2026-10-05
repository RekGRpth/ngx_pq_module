#!/bin/sh -eu

# Build ngx_pq_module with AddressSanitizer and run the test suite against it.
#
# Usage: t/asan.sh [prove options] [t/file.t ...]
#   NGINX_SRC  configured nginx source tree with this module (default: $HOME/src/nginx)
#   KEEP=1     keep the temporary directory (build, test copies, ASan reports)
#
# The installed nginx binary is used as is; only the module is instrumented,
# with libasan preloaded. Exits non-zero if a test fails or ASan reports anything.

cd "$(dirname "$0")/.."
src=$(pwd)
nginx=${NGINX_SRC:-$HOME/src/nginx}
out=$(mktemp -d)
[ "${KEEP:-}" = 1 ] || trap 'rm -rf "${out:?}"' EXIT
libasan=$(cc -print-file-name=libasan.so)

# the module's own compile and link commands (as if only its source changed),
# with the outputs moved to $out and ASan flags added
module=$(grep -o '[^ 	]*ngx_pq_module\.c' "$nginx/objs/Makefile" | head -n 1)
(cd "$nginx" && make -n -W "$module" -f objs/Makefile objs/ngx_pq_module.so 2>/dev/null) \
    | sed -e "s#^cc -c #cc -c -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer #" \
          -e "s#^cc -o #cc -fsanitize=address -o #" \
          -e "s#objs/addon/ngx_pq_module/ngx_pq_module\.o#$out/ngx_pq_module.o#g" \
          -e "s#objs/ngx_pq_module\.so#$out/ngx_pq_module.so#g" \
    > "$out/build.sh"
(cd "$nginx" && sh -e "$out/build.sh")
nm -D --undefined-only "$out/ngx_pq_module.so" | grep -q __asan

mkdir "$out/t"
for f in t/*.t; do
    sed "s#/etc/nginx/modules/ngx_pq_module\.so#$out/ngx_pq_module.so#" "$f" > "$out/$f"
done
[ $# -gt 0 ] || set -- t/*.t

status=0
(cd "$out" && LD_PRELOAD="$libasan" ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=$out/asan" prove "$@") || status=$?

if ls "$out"/asan.* >/dev/null 2>&1; then
    cat "$out"/asan.* >&2
    echo "AddressSanitizer: $(ls "$out"/asan.* | wc -l) report(s)" >&2
    [ "${KEEP:-}" = 1 ] && echo "kept in $out" >&2
    exit 1
fi
echo "AddressSanitizer: no reports"
[ "${KEEP:-}" = 1 ] && echo "kept in $out"
exit $status
