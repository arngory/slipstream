"""Random mutations of a tunnel query: mutate.py PORT DOMAIN COUNT SEED."""
import socket, struct, os, random, sys, base64
port=int(sys.argv[1]); domain=sys.argv[2]; n=int(sys.argv[3])
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1<<22)
def name(n): return b''.join(bytes([len(l)])+l for l in n.encode().split(b'.'))+b'\0'
pkt=os.urandom(120)
b=base64.b32encode(pkt).decode().rstrip('=').lower()
qn='.'.join(b[i:i+57] for i in range(0,len(b),57))+'.'+domain
base=struct.pack('>HHHHHH',1,0x100,1,0,0,1)+name(qn)+struct.pack('>HH',16,1)+b'\0'+struct.pack('>HHIH',41,1232,0x8000,4)+b'\x00\x0a\x00\x00'
random.seed(int(sys.argv[4]))
for k in range(n):
    m=bytearray(base)
    for _ in range(random.randint(1,6)):
        op=random.random()
        if op<0.5 and m: m[random.randrange(len(m))]=random.randrange(256)
        elif op<0.7 and m: del m[random.randrange(len(m)):]
        elif op<0.85: m[random.randrange(len(m)+1):0]=os.urandom(random.randint(1,8))
        else:
            i=random.randrange(12) if len(m)>12 else 0
            if len(m)>i: m[i]=random.choice([0,1,2,0xff,0xc0,0x80,0x7f])
    s.sendto(bytes(m),('127.0.0.1',port))
print('sent',n)
