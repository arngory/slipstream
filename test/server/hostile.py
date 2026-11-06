"""Queries that ended the upstream server, and a flood of long headers of
another version: hostile.py PORT DOMAIN. The server must stay up."""
import socket, struct, os, random, sys
port=int(sys.argv[1]); domain=sys.argv[2]
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.3)
def name(n):
    return b''.join(bytes([len(l)])+l for l in n.encode().split(b'.'))+b'\0'
def q(qname, qtype=16, qclass=1, flags=0x0100, opt=None, extra=b'', counts=None):
    body=name(qname)+struct.pack('>HH',qtype,qclass)
    ar=0
    if opt is not None:
        body+=b'\0'+struct.pack('>HHIH',41,opt,0x8000,0); ar=1
    qd,an,ns=1,0,0
    if counts: qd,an,ns,ar=counts
    return struct.pack('>HHHHHH',random.randrange(65536),flags,qd,an,ns,ar)+body+extra
cases={
 'garbage': os.urandom(200),
 'empty': b'',
 'short': b'\x01\x02\x03',
 'class ANY': q('abc.'+domain, qclass=255),
 'class CH': q('abc.'+domain, qclass=3),
 'qtype OPT': q('abc.'+domain, qtype=41),
 'opcode 5': q('abc.'+domain, flags=0x2800),
 'opcode 15': q('abc.'+domain, flags=0x7800),
 'response bit': q('abc.'+domain, flags=0x8100),
 'two questions': q('abc.'+domain, counts=(2,0,0,0)),
 'zero questions': struct.pack('>HHHHHH',1,0x100,0,0,0,0),
 'bad base32': q('a1b!.'+domain),
 'other zone': q('abc.other.example'),
 'apex': q(domain),
 'only dots base32 len1': q('a.'+domain),
 'A query': q('abc.'+domain, qtype=1),
 'with OPT DO': q('aaaaaaaa.'+domain, opt=1232),
 'counts lie': q('abc.'+domain, counts=(1,5,5,5)),
 'long name': q('.'.join(['a'*63]*3)+'.'+domain),
 'random long header quic': None,
}
import base64
# a long-header QUIC packet of an unknown version, base32 in the name: VN queue
pkt=bytes([0xc0])+b'\x1a\x2b\x3c\x4d'+b'\x08'+os.urandom(8)+b'\x08'+os.urandom(8)+os.urandom(80)
b=base64.b32encode(pkt).decode().rstrip('=').lower()
labels=[b[i:i+57] for i in range(0,len(b),57)]
cases['random long header quic']=q('.'.join(labels)+'.'+domain)
for k,v in cases.items():
    s.sendto(v,('127.0.0.1',port))
    try:
        r,_=s.recvfrom(4096)
        rc=r[3]&0xf; tc=(r[2]>>1)&1; ar=struct.unpack('>H',r[10:12])[0]
        print(f'{k:28s} answer rcode={rc} ancount={struct.unpack(">H",r[6:8])[0]} arcount={ar} len={len(r)}')
    except socket.timeout:
        print(f'{k:28s} no answer')
for i in range(3000):
    s.sendto(q('.'.join(labels)+'.'+domain),('127.0.0.1',port))
print('flood sent')
