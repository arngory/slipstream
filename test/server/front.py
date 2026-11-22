"""A stand-in for the DNS front (niko-server "packet" mode) in tests.

front.py UDP_PORT SOCKET TAG_LEN DOMAIN [DEVICE]: takes DNS queries on
127.0.0.1:UDP_PORT and hands them to slipstream-server --front-socket SOCKET
with the IPC v1 header, or with DEVICE the v2 one naming that device (its
first 8 bytes, as the front names a device whose tag it checked). Ports and
devices may be lists (25320,25321 dev-a,dev-b): a port's queries are its
device's (the server takes one front at a time). With TAG_LEN > 0 it puts that many random bytes before the QUIC
packet in the name (as a client signing with dnsauth-v2 would), in place of
a label that starts with "pppp" (give the client a domain such as
pppppppppppppppp.<DOMAIN>, so that its names leave room), and gives the
client back its own question.
"""
import socket, struct, sys, os, base64, threading, select
ports=[int(p) for p in sys.argv[1].split(',')]; sock_path=sys.argv[2]; tag=int(sys.argv[3]); domain=sys.argv[4]
devices=[d.encode()[:8].ljust(8, b'\0') for d in sys.argv[5].split(',')] if len(sys.argv) > 5 else [None]*len(ports)
socks=[]
for p in ports:
    s_=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s_.bind(('127.0.0.1',p)); socks.append(s_)
udp_port=ports[0]; u=socks[0]
via={}  # client -> the socket its queries came in on, for its answers
import time
while True:
    try:
        b=socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); b.connect(sock_path); break
    except OSError: time.sleep(0.1)
def addr(a):
    ip,port=a
    return b'\x04'+b'\0'*10+b'\xff\xff'+socket.inet_aton(ip)+struct.pack('>H',port)
def unaddr(b):
    return (socket.inet_ntoa(b[13:17]), struct.unpack('>H',b[17:19])[0])
local=('127.0.0.1',udp_port)
orig={}  # (client,id) -> original question bytes
def qend(m):
    i=12
    while m[i]: i+=m[i]+1
    return i+5
def retag(m):
    e=qend(m); i=12; labels=[]
    while m[i]: labels.append(m[i+1:i+1+m[i]]); i+=m[i]+1
    zl=len(domain.split('.'))
    pad=1 if labels[-zl-1].startswith(b'pppp') else 0
    data=b''.join(labels[:-zl-pad]).decode().upper()
    raw=base64.b32decode(data+'='*((8-len(data)%8)%8))
    enc=base64.b32encode(os.urandom(tag)+raw).decode().rstrip('=').lower()
    name=b''.join(bytes([len(x)])+x.encode() for x in [enc[j:j+57] for j in range(0,len(enc),57)])
    name+=b''.join(bytes([len(x)])+x for x in labels[-zl:])+b'\0'
    return m[:12]+name+m[e-4:]
def back():
    while True:
        msg=b.recv(70000)
        if not msg: os._exit(1)
        assert msg[:3]==b'NU\x01'
        client=unaddr(msg[3:22]); ans=bytearray(msg[41:])
        if tag:
            k=(client,ans[:2].hex()); o=orig.pop(k,None)
            if o is None: continue
            e=qend(ans); ans=ans[:12]+o+ans[e:]
        via.get(client, u).sendto(bytes(ans),client)
threading.Thread(target=back,daemon=True).start()
while True:
    ready,_,_=select.select(socks,[],[])
    us=ready[0]; device=devices[socks.index(us)]
    m,c=us.recvfrom(4096); via[c]=us
    if tag:
        try:
            orig[(c,m[:2].hex())]=m[12:qend(m)]; m=retag(m)
        except Exception as ex:
            continue
    if device is None:
        b.send(b'NU\x01'+addr(c)+addr(local)+m)
    else:
        b.send(b'NU\x02'+addr(c)+addr(local)+device+m)
