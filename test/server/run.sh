#!/usr/bin/env bash
# Server checks (docs/server-front.md): echo through the tunnel over UDP and
# through a DNS front, with and without a device tag; hostile and mutated
# queries do not end the server; a stranger on the front socket is refused;
# SSLKEYLOGFILE writes nothing.
#
#   test/server/run.sh [BUILD_DIR]     (default: build)
#
# SLIPSTREAM_SERVER: another server binary (the static build) against the
# client of BUILD_DIR.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
build="$(cd "${1:-build}" && pwd)"
server_bin="$(realpath "${SLIPSTREAM_SERVER:-$build/slipstream-server}")"
work="$(mktemp -d)"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem \
  -days 1 -subj /CN=x 2>/dev/null
python3 "$here/echo.py" 25201 & pids+=($!)
server() { "$server_bin" -a 127.0.0.1:25201 -c cert.pem -k key.pem -d t.example -n picoquic_sample "$@" & pids+=($!); }
echo_through() { # port
  timeout 90 python3 - "$1" <<'PY'
import socket, os, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=60)
data = os.urandom(200000); s.sendall(data); got = b""
while len(got) < len(data):
    d = s.recv(65536)
    if not d: break
    got += d
sys.exit(0 if got == data else 1)
PY
}
fail() { echo "FAIL: $*"; exit 1; }

# UDP, hostile queries, mutations; SSLKEYLOGFILE ignored
SSLKEYLOGFILE="$work/keys.log" server -l 25300 -b 127.0.0.1 >udp.log 2>&1
udp=${pids[-1]}
sleep 0.5
python3 "$here/hostile.py" 25300 t.example >/dev/null
for seed in 1 2; do python3 "$here/mutate.py" 25300 t.example 20000 $seed >/dev/null; done
sleep 0.5
kill -0 "$udp" || fail "the server ended on hostile queries: $(tail -2 udp.log)"
"$build/slipstream-client" -l 25400 -r 127.0.0.1:25300 -d t.example >client-udp.log 2>&1 & pids+=($!)
sleep 2
echo_through 25400 || fail "echo over UDP"
[ ! -e keys.log ] || fail "SSLKEYLOGFILE was written"
echo "ok: UDP echo, hostile and mutated queries, no key log"

# a DNS front, without and with a device tag
for tag in 0 8; do
  sock="$work/front$tag.sock"
  server -f "$sock" -u "$(id -u)" -t "$tag" >front$tag.log 2>&1
  sleep 0.3
  [ "$(stat -c %a "$sock")" = 660 ] || fail "front socket mode"
  python3 "$here/front.py" $((25310 + tag)) "$sock" "$tag" t.example & pids+=($!)
  sleep 0.3
  domain=t.example; [ "$tag" = 0 ] || domain=pppppppppppppppp.t.example
  "$build/slipstream-client" -l $((25410 + tag)) -r 127.0.0.1:$((25310 + tag)) -d "$domain" >client$tag.log 2>&1 & pids+=($!)
  sleep 2
  echo_through $((25410 + tag)) || fail "echo through the front, tag $tag"
  echo "ok: echo through the front, tag $tag"
done

# a stranger on the front socket
server -f "$work/uid.sock" -u 4242 >uid.log 2>&1
sleep 0.3
python3 -c "
import socket, sys; b = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); b.connect(sys.argv[1]); b.settimeout(2)
sys.exit(0 if b.recv(10) == b'' else 1)" "$work/uid.sock" || fail "a stranger was taken"
grep -q 'refused' uid.log || fail "no refusal logged"
echo "ok: a stranger on the front socket refused"
