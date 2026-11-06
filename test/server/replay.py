"""Copies of a client's queries from another address, as anyone on the path
could send them (slipstream-v1 §1 item 5).

replay.py UDP_PORT SERVER_PORT STATUS_FILE: a UDP proxy on 127.0.0.1:UDP_PORT
to the server on 127.0.0.1:SERVER_PORT. Each query goes on as it came, and
once it has been answered, a copy with another ID goes from a second socket,
and again 2 s later.
A copy must get an empty answer: the server already had its packet, and the
connection's next packet belongs to the client. STATUS_FILE gets
"copies N with-data M" as they come.
"""
import socket, struct, sys, threading
port, server_port, status = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
server = ('127.0.0.1', server_port)
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(('127.0.0.1', port))
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # the client's side, to the server
spy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # the copies
client = None
lock = threading.Lock()
pending = {}  # question -> query, until answered
copies = with_data = 0


def question(m):
    i = 12
    while i < len(m) and m[i]:
        i += m[i] + 1
    return m[12:i + 5].lower()


def ancount(m):
    return struct.unpack('>H', m[6:8])[0] if len(m) >= 12 else 0


def answers():
    global copies, with_data
    while True:
        m, _ = up.recvfrom(4096)
        if client is not None:
            front.sendto(m, client)
        with lock:
            q = pending.pop(question(m), None)
        if q is not None:
            # The copy goes once the original is answered: the server took
            # its packet by then. Another goes 2 s later, when picoquic has
            # forgotten the packet's number (review).
            c = bytes([q[0] ^ 0x5a, q[1]]) + q[2:]
            spy.sendto(c, server)
            threading.Timer(2.0, spy.sendto, (c, server)).start()


def copy_answers():
    global copies, with_data
    while True:
        m, _ = spy.recvfrom(4096)
        copies += 1
        if ancount(m) > 0:
            with_data += 1
            with open(status + '.data', 'a') as f:
                f.write(question(m)[:80].hex() + '\n')
        with open(status, 'w') as f:
            f.write(f'copies {copies} with-data {with_data}\n')


threading.Thread(target=answers, daemon=True).start()
threading.Thread(target=copy_answers, daemon=True).start()
while True:
    m, c = front.recvfrom(4096)
    client = c
    with lock:
        if len(pending) > 4096:
            pending.clear()
        pending[question(m)] = m
    up.sendto(m, server)
