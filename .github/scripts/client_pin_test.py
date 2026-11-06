#!/usr/bin/env python3
"""The client on the loopback against the server (slipstream-v1).

TLS: the pinned key carries the request whatever the SNI says, another key and a client without --pin (and without
--insecure) carry nothing, the client listens on the loopback only. Streams through the pinned client: one after
another and side by side, a request ended by a half-close still gets its answer, and a large upload and download
arrive whole. Usage: client_pin_test.py <the meson build directory>."""
import base64
import hashlib
import os
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


def start(name, args):
    log = open(os.path.join(WORK, name + ".log"), "wb")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
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


def client(name, port, *extra):
    return start(name, [CLIENT, "--congestion-control=bbr", "--tcp-listen-port=%d" % port,
                        "--resolver=127.0.0.1:%d" % DNS_PORT, "--domain=" + DOMAIN, *extra])


def refused_at_start(name, *extra):
    """a client that must not start: exit code and what it says"""
    run = subprocess.run([CLIENT, "--resolver=127.0.0.1:%d" % DNS_PORT, "--domain=" + DOMAIN, "--tcp-listen-port=7999",
                          *extra], capture_output=True, timeout=20)
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

    # the pin decides, the name is a cover: any SNI
    client("pinned", 7001, "--pin=" + pin, "--sni=cdn.example.net")
    client("insecure", 7002, "--insecure")
    client("other key", 7003, "--pin=" + other_pin)
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

if failures:
    sys.exit("\n".join(failures))
print("the pin holds, the streams arrive whole")
