#!/usr/bin/env python3
"""The client on the loopback against the server (slipstream-v1).

TLS: the pinned key carries the request whatever the SNI says, another key and a client without --pin (and without
--insecure) carry nothing, the client listens on the loopback only. Streams through the pinned client: one after
another and side by side, a request ended by a half-close still gets its answer, and a large upload and download
arrive whole. dnsauth-v2: through a front that checks the field on every query and passes the packet on without it,
the device's key carries the request, another key or another clock does not. Usage: client_pin_test.py <the meson
build directory>."""
import base64
import hashlib
import hmac
import os
import struct
import socket
import subprocess
import sys
import tempfile
import threading
import time

BUILD = sys.argv[1]
CLIENT = os.path.join(BUILD, "slipstream-client")
SERVER = os.path.join(BUILD, "slipstream-server")
DOMAIN = "tunnel.test"
DNS_PORT, TARGET_PORT = 8853, 5201
WORK = tempfile.mkdtemp()
procs = []


def cert(name):
    """a self-signed P-256 certificate and the pin of its key: base64url SHA-256 of the SubjectPublicKeyInfo"""
    key, crt = os.path.join(WORK, name + "-key.pem"), os.path.join(WORK, name + "-cert.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=" + name], check=True, capture_output=True)
    pub = subprocess.run(["openssl", "x509", "-in", crt, "-pubkey", "-noout"], check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, check=True,
                         capture_output=True).stdout
    return key, crt, base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


# dnsauth-v2's vector key (raycontrol docs/spec/dnsauth-v2.md §6)
DNSAUTH_KEY = "0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c"


def dnsauth_field(key, epoch, msg):
    """hint (2) || tag (6), as the spec has it"""
    e = struct.pack(">I", epoch)
    return (hmac.new(key, b"dnsauth2-hint" + e, hashlib.sha256).digest()[:2] +
            hmac.new(key, b"dnsauth2-tag" + e + msg, hashlib.sha256).digest()[:6])


assert dnsauth_field(bytes.fromhex(DNSAUTH_KEY), 2945448, bytes(range(24))).hex() == "2d82b1220002a927"


def strip_field(query, key):
    """the query to pass on without its dnsauth-v2 field, or None when the field is not the key's"""
    labels, off = [], 12
    while query[off] != 0:
        n = query[off]
        if n & 0xC0:
            return None
        labels.append(query[off + 1:off + 1 + n])
        off += 1 + n
    end = off + 1
    zone = DOMAIN.encode().split(b".")
    if [label.lower() for label in labels[-len(zone):]] != zone or len(labels) <= len(zone):
        return None
    text = b"".join(labels[:-len(zone)]).upper()
    try:
        data = base64.b32decode(text + b"=" * (-len(text) % 8))
    except ValueError:
        return None
    field, packet = data[:8], data[8:]
    epoch = int(time.time()) // 600
    if len(field) < 8 or not any(hmac.compare_digest(field, dnsauth_field(key, e, packet))
                                 for e in (epoch - 1, epoch, epoch + 1)):
        return None
    text = base64.b32encode(packet).rstrip(b"=")
    parts = [text[i:i + 57] for i in range(0, len(text), 57)] + zone
    return query[:12] + b"".join(bytes([len(p)]) + p for p in parts) + b"\0" + query[end:]


def front(port, key_hex):
    """the node's front, as much as dnsauth-v2 needs: a query passes to the server only with the key's field, and
    without it; the server's answer goes back as it is"""
    key = bytes.fromhex(key_hex)
    counters = {"passed": 0, "refused": 0}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.connect(("127.0.0.1", DNS_PORT))
    clients = {}

    def answers():
        while True:
            answer = up.recv(4096)
            addr = clients.get(answer[:2])
            if addr is not None:
                sock.sendto(answer, addr)

    def queries():
        while True:
            query, addr = sock.recvfrom(4096)
            passed = strip_field(query, key)
            if passed is None:
                counters["refused"] += 1
                continue
            counters["passed"] += 1
            clients[query[:2]] = addr
            up.send(passed)

    threading.Thread(target=answers, daemon=True).start()
    threading.Thread(target=queries, daemon=True).start()
    return counters


def pattern(n):
    return bytes(i % 251 for i in range(n))


def target():
    """the service behind the server. "upload": reads to the end, answers its size and SHA-256; "download N": sends N
    bytes of the pattern; any other line: answered back"""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", TARGET_PORT))
    listener.listen()

    def answer(conn):
        with conn:
            reader = conn.makefile("rb")
            line = reader.readline()
            if line == b"upload\n":
                data = reader.read()
                conn.sendall(b"got %d %s\n" % (len(data), hashlib.sha256(data).hexdigest().encode()))
            elif line.startswith(b"download "):
                conn.sendall(pattern(int(line.split()[1])))
            else:
                conn.sendall(b"answer to " + line)

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=answer, args=(conn,), daemon=True).start()


def start(name, args, env=None):
    log = open(os.path.join(WORK, name + ".log"), "wb")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                            env=None if env is None else {**os.environ, **env})
    procs.append((name, proc))
    return proc


def exchange(port, request, half_close, timeout):
    """one connection through the client on port: the request, the half-close if asked, then all the answer"""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.settimeout(timeout)
        conn.sendall(request)
        if half_close:
            conn.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return data
            data += chunk


def ask(port, deadline, request=b"hello\n"):
    """the answer through the client on port, or b"" when none came before the deadline"""
    while time.monotonic() < deadline:
        try:
            data = exchange(port, request, False, max(1.0, deadline - time.monotonic()))
            if data:
                return data
        except OSError:
            pass
        time.sleep(1)
    return b""


def check(name, got, want):
    shown = got if len(got) <= 80 else b"%d bytes" % len(got)
    print("%s: %r" % (name, shown))
    if got != want:
        failures.append("%s: %r, want %r" % (name, shown, want if len(want) <= 80 else b"%d bytes" % len(want)))


def client(name, port, *extra, resolver=DNS_PORT, env=None):
    return start(name, [CLIENT, "--congestion-control=bbr", "--tcp-listen-port=%d" % port,
                        "--resolver=127.0.0.1:%d" % resolver, "--domain=" + DOMAIN, *extra], env)


def refused_at_start(name, *extra, env=None):
    """a client that must not start: exit code and what it says"""
    run = subprocess.run([CLIENT, "--resolver=127.0.0.1:%d" % DNS_PORT, "--domain=" + DOMAIN, "--tcp-listen-port=7999",
                          *extra], capture_output=True, timeout=20, env=None if env is None else {**os.environ, **env})
    if run.returncode == 0:
        sys.exit("%s: the client started (%s)" % (name, run.stdout.decode(errors="replace")))
    print("%s: refused, %s" % (name, (run.stderr or run.stdout).decode(errors="replace").strip()))


failures = []
try:
    key, crt, pin = cert("server")
    _, _, other_pin = cert("other")
    threading.Thread(target=target, daemon=True).start()
    start("server", [SERVER, "--dns-listen-port=%d" % DNS_PORT, "--dns-listen-address=127.0.0.1",
                     "--target-address=127.0.0.1:%d" % TARGET_PORT, "--cert=" + crt, "--key=" + key,
                     "--domain=" + DOMAIN])
    time.sleep(1)

    refused_at_start("no --pin", )
    refused_at_start("--pin and --insecure", "--pin=" + pin, "--insecure")
    refused_at_start("a short pin", "--pin=" + pin[:20])
    refused_at_start("not base64url", "--pin=" + "!" * 43)
    refused_at_start("not an IPv4 listen address", "--pin=" + pin, "--tcp-listen-host=localhost")
    refused_at_start("--dnsauth without its key", "--pin=" + pin, "--dnsauth")
    refused_at_start("a short dnsauth key", "--pin=" + pin, "--dnsauth", env={"SLIPSTREAM_DNSAUTH_KEY": "0b48"})
    refused_at_start("a dnsauth key without --dnsauth", "--pin=" + pin, env={"SLIPSTREAM_DNSAUTH_KEY": DNSAUTH_KEY})

    # the pin decides, the name is a cover: any SNI
    client("pinned", 7001, "--pin=" + pin, "--sni=cdn.example.net")
    client("insecure", 7002, "--insecure")
    client("other key", 7003, "--pin=" + other_pin)
    # a pin may start with "-" (one key in 64): given with "=", it is the pin, not options (the app passes it so);
    # this one is not the server's, and the client says so with its own exit code, not the arguments' 1
    client("a pin starting with -", 7008, "--pin=-" + other_pin[1:])
    time.sleep(2)

    listening = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True).stdout
    for port in (7001, 7002):
        if "127.0.0.1:%d " % port not in listening:
            failures.append("the client on %d does not listen on 127.0.0.1:\n%s" % (port, listening))

    for name, port, want in (("pinned", 7001, b"answer to hello\n"), ("insecure", 7002, b"answer to hello\n"),
                             ("other key", 7003, b"")):
        check(name, ask(port, time.monotonic() + (60 if want else 20)), want)

    # the other key: the client says so and ends with its own exit code
    other = dict(procs)["other key"]
    try:
        other.wait(timeout=30)
    except subprocess.TimeoutExpired:
        failures.append("other key: the client still runs")
    if other.returncode != 3:
        failures.append("other key: exit %s, want 3 (the server's key is not the pinned one)" % other.returncode)
    dash = dict(procs)["a pin starting with -"]
    try:
        dash.wait(timeout=30)
    except subprocess.TimeoutExpired:
        failures.append("a pin starting with -: the client still runs")
    if dash.returncode != 3:
        failures.append("a pin starting with -: exit %s, want 3 (taken as the pin, not the server's)" % dash.returncode)

    # the streams through the pinned client, now connected
    for i in range(20):
        request = b"hello %d\n" % i
        check("one after another %d" % i, exchange(7001, request, False, 30), b"answer to " + request)

    answers = {}

    def side_by_side(i):
        request = b"side by side %d\n" % i
        try:
            answers[i] = (exchange(7001, request, False, 60), b"answer to " + request)
        except OSError as e:
            answers[i] = (repr(e).encode(), b"answer to " + request)

    threads = [threading.Thread(target=side_by_side, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for i in sorted(answers):
        check("side by side %d" % i, *answers[i])

    # the request ends with a half-close: the answer still comes (a reset in its place lost it)
    empty = hashlib.sha256(b"").hexdigest().encode()
    check("a half-close", exchange(7001, b"upload\n", True, 30), b"got 0 " + empty + b"\n")
    upload = pattern(512 * 1024)
    started = time.monotonic()
    check("an upload", exchange(7001, b"upload\n" + upload, True, 180),
          b"got %d %s\n" % (len(upload), hashlib.sha256(upload).hexdigest().encode()))
    print("  %.1f s" % (time.monotonic() - started))
    started = time.monotonic()
    check("a download", exchange(7001, b"download %d\n" % (1024 * 1024), False, 180), pattern(1024 * 1024))
    print("  %.1f s" % (time.monotonic() - started))
    check("after them", exchange(7001, b"hello again\n", False, 30), b"answer to hello again\n")

    # dnsauth-v2 through a front: the device's key passes, another key and a clock an hour off do not
    tagged_front = front(8854, DNSAUTH_KEY)
    other_front = front(8855, DNSAUTH_KEY)
    clock_front = front(8856, DNSAUTH_KEY)
    behind_front = front(8857, DNSAUTH_KEY)
    client("tagged", 7004, "--pin=" + pin, "--dnsauth", resolver=8854, env={"SLIPSTREAM_DNSAUTH_KEY": DNSAUTH_KEY})
    client("tagged, another key", 7005, "--pin=" + pin, "--dnsauth", resolver=8855,
           env={"SLIPSTREAM_DNSAUTH_KEY": "11" * 32})
    client("quiet", 7007, "--pin=" + pin, "--quiet")
    client("tagged, another clock", 7006, "--pin=" + pin, "--dnsauth", "--clock-offset=3600", resolver=8856,
           env={"SLIPSTREAM_DNSAUTH_KEY": DNSAUTH_KEY})
    # the node's clock behind this one: a negative offset (the app gives it with "=", as every value)
    client("tagged, the clock behind", 7009, "--pin=" + pin, "--dnsauth", "--clock-offset=-3600", resolver=8857,
           env={"SLIPSTREAM_DNSAUTH_KEY": DNSAUTH_KEY})
    check("tagged", ask(7004, time.monotonic() + 60), b"answer to hello\n")
    upload = pattern(256 * 1024)
    check("tagged, an upload", exchange(7004, b"upload\n" + upload, True, 180),
          b"got %d %s\n" % (len(upload), hashlib.sha256(upload).hexdigest().encode()))
    check("tagged, another key", ask(7005, time.monotonic() + 20), b"")
    check("tagged, another clock", ask(7006, time.monotonic() + 20), b"")
    check("tagged, the clock behind", ask(7009, time.monotonic() + 20), b"")
    # its arguments taken: not the arguments' exit 1 (its handshake, refused at the front, gives up with 2 after 30 s;
    # that the front saw its queries is checked below)
    if dict(procs)["tagged, the clock behind"].poll() == 1:
        failures.append("tagged, the clock behind: exit 1, its arguments refused")
    check("quiet", ask(7007, time.monotonic() + 60), b"answer to hello\n")
    print("fronts: the key %s, another key %s, another clock %s" % (tagged_front, other_front, clock_front))
    if tagged_front["passed"] == 0 or tagged_front["refused"] != 0:
        failures.append("the key's front: %s, want every query passed" % tagged_front)
    for name, counters in (("another key", other_front), ("another clock", clock_front),
                           ("the clock behind", behind_front)):
        if counters["passed"] != 0 or counters["refused"] == 0:
            failures.append("%s: the front %s, want every query refused" % (name, counters))
finally:
    for name, proc in procs:
        proc.terminate()
    for name, proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        with open(os.path.join(WORK, name + ".log"), "rb") as log:
            tail = log.read()[-3000:].decode(errors="replace")
        print("--- %s (exit %s)\n%s" % (name, proc.returncode, tail))

# --quiet: nothing on stdout, the streams it carried included (start() puts stdout and stderr in one log, and stderr
# is empty when all went well)
with open(os.path.join(WORK, "quiet.log"), "rb") as log:
    quiet_log = log.read()
if quiet_log.strip():
    failures.append("quiet: it wrote %r" % quiet_log[:300])

if failures:
    sys.exit("\n".join(failures))
print("the pin holds, the streams arrive whole")
