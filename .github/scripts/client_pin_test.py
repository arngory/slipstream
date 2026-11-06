#!/usr/bin/env python3
"""The client's TLS toward the server on the loopback (slipstream-v1): the pinned key carries the request whatever the
SNI says, another key and a client without --pin (and without --insecure) carry nothing, and the client listens on
the loopback only. Usage: client_pin_test.py <the meson build directory>."""
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


def target():
    """the service behind the server: it answers the line it is sent"""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", TARGET_PORT))
    listener.listen()

    def answer(conn):
        with conn:
            line = conn.makefile("rb").readline()
            conn.sendall(b"answer to " + line)

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=answer, args=(conn,), daemon=True).start()


def start(name, args):
    log = open(os.path.join(WORK, name + ".log"), "wb")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    procs.append((name, proc))
    return proc


def ask(port, deadline):
    """the answer through the client on port, or b"" when none came before the deadline"""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                conn.settimeout(max(1.0, deadline - time.monotonic()))
                conn.sendall(b"hello\n")
                data = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                if data:
                    return data
        except OSError:
            pass
        time.sleep(1)
    return b""


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
        got = ask(port, time.monotonic() + (60 if want else 20))
        print("%s: %r" % (name, got))
        if got != want:
            failures.append("%s: %r, want %r" % (name, got, want))
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
print("the pin holds")
