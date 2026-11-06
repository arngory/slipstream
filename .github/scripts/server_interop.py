#!/usr/bin/env python3
"""This branch's client against the hardened server (server/hardening): the dnsauth-v2 field the server takes off
(--tag-len 8, the node's front has checked it), the server's ALPN required, streams whole both ways, a half-close's
answer; another ALPN fails the handshake (exit 2), a client without the field gets nothing through.
Usage: server_interop.py <the client's build directory> <the server's build directory>."""
import base64
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

CLIENT = os.path.join(sys.argv[1], "slipstream-client")
SERVER = os.path.join(sys.argv[2], "slipstream-server")
DOMAIN, ALPN = "tunnel.test", "k3x9q2p7m1"
DNS_PORT, TARGET_PORT = 8953, 5301
KEY = "0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c"
WORK = tempfile.mkdtemp()
procs, failures = [], []


def cert():
    key, crt = os.path.join(WORK, "key.pem"), os.path.join(WORK, "cert.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=s"], check=True, capture_output=True)
    pub = subprocess.run(["openssl", "x509", "-in", crt, "-pubkey", "-noout"], check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, check=True,
                         capture_output=True).stdout
    return key, crt, base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def pattern(n):
    return bytes(i % 251 for i in range(n))


def target():
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


def client(name, port, *extra, env=None):
    return start(name, [CLIENT, "--tcp-listen-port=%d" % port, "--resolver=127.0.0.1:%d" % DNS_PORT,
                        "--domain=" + DOMAIN, "--quiet", *extra], env)


try:
    key, crt, pin = cert()
    threading.Thread(target=target, daemon=True).start()
    start("server", [SERVER, "-l", str(DNS_PORT), "-b", "127.0.0.1", "-a", "127.0.0.1:%d" % TARGET_PORT, "-c", crt,
                     "-k", key, "-d", DOMAIN, "-n", ALPN, "-t", "8"])
    time.sleep(1)
    tagged = {"SLIPSTREAM_DNSAUTH_KEY": KEY}
    client("tagged", 7101, "--pin=" + pin, "--alpn=" + ALPN, "--sni=cdn.example.net", "--dnsauth", env=tagged)
    other_alpn = client("another ALPN", 7102, "--pin=" + pin, "--alpn=picoquic_sample", "--dnsauth", env=tagged)
    client("no field", 7103, "--pin=" + pin, "--alpn=" + ALPN)

    check("tagged", ask(7101, time.monotonic() + 60), b"answer to hello\n")
    for i in range(10):
        request = b"hello %d\n" % i
        check("one after another %d" % i, exchange(7101, request, False, 30), b"answer to " + request)
    empty = hashlib.sha256(b"").hexdigest().encode()
    check("a half-close", exchange(7101, b"upload\n", True, 30), b"got 0 " + empty + b"\n")
    upload = pattern(256 * 1024)
    check("an upload", exchange(7101, b"upload\n" + upload, True, 180),
          b"got %d %s\n" % (len(upload), hashlib.sha256(upload).hexdigest().encode()))
    check("a download", exchange(7101, b"download %d\n" % (512 * 1024), False, 180), pattern(512 * 1024))

    check("another ALPN", ask(7102, time.monotonic() + 20), b"")
    try:
        other_alpn.wait(timeout=40)
    except subprocess.TimeoutExpired:
        failures.append("another ALPN: the client still runs")
    if other_alpn.returncode != 2:
        failures.append("another ALPN: exit %s, want 2 (the handshake failed)" % other_alpn.returncode)
    check("no field", ask(7103, time.monotonic() + 20), b"")
finally:
    for name, proc in procs:
        proc.terminate()
    for name, proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        with open(os.path.join(WORK, name + ".log"), "rb") as log:
            print("--- %s (exit %s)\n%s" % (name, proc.returncode, log.read()[-2000:].decode(errors="replace")))

if failures:
    sys.exit("\n".join(failures))
print("the client and the hardened server agree")
