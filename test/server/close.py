"""Connections that hold no place (reviews of --max-connections-per-device).
As the DNS front (IPC version 2) for device dev-a, COUNT connections that
picoquic makes but that must not keep a place of the server's or the
device's:

  close   an Initial with the start of a ClientHello, then one with a
          CONNECTION_CLOSE: closed in the handshake (its context outlived it
          and locked the device out for good);
  fail    the same, then an Initial with a STREAM frame: the handshake
          fails (held to the handshake's 10 s, uncounted);
  orphan  a datagram of two Initials with different connection IDs:
          picoquic makes the second's connection, then refuses the segment
          (nothing took it; held 10 s).

close.py SOCKET DOMAIN [MODE [COUNT]] (MODE close, fail, orphan or all;
default close 1), the server with --tag-len 8 (needs python3-cryptography)"""
import socket, struct, sys, os, time, base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SALT = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
def extract(salt, ikm):
    h = hmac.HMAC(salt, hashes.SHA256()); h.update(ikm); return h.finalize()
def expand_label(secret, label, length):
    full = b'tls13 ' + label.encode()
    info = struct.pack('!H', length) + bytes([len(full)]) + full + b'\x00'
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)
def keys(dcid):
    s = expand_label(extract(SALT, dcid), 'client in', 32)
    return expand_label(s, 'quic key', 16), expand_label(s, 'quic iv', 12), expand_label(s, 'quic hp', 16)
def initial(dcid, scid, pn, payload, pad=90):
    key, iv, hp = keys(dcid)
    pn_len = 4
    payload = payload + b'\x00' * max(0, pad - len(payload))  # PADDING
    length = pn_len + len(payload) + 16
    hdr = bytes([0xc0 | (pn_len - 1)]) + struct.pack('!I', 1) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    hdr += b'\x00' + struct.pack('!H', 0x4000 | length)
    pn_off = len(hdr)
    hdr += struct.pack('!I', pn)
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, 'big')))
    ct = AESGCM(key).encrypt(nonce, payload, hdr)
    pkt = bytearray(hdr + ct)
    sample = bytes(pkt[pn_off + 4: pn_off + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    pkt[0] ^= mask[0] & 0x0f
    for i in range(pn_len):
        pkt[pn_off + i] ^= mask[1 + i]
    return bytes(pkt)
def crypto_frame(data):
    return b'\x06\x00' + bytes([0x40 | (len(data) >> 8), len(data) & 0xff]) + data
def partial_client_hello():
    return b'\x01\x00\x01\x2c' + b'\x03\x03' + os.urandom(32)  # type, length 300, version, random: incomplete
def query(pkt, domain):
    # The dnsauth-v2 field the front checked first (the server, -t 8, skips it).
    name = base64.b32encode(os.urandom(8) + pkt).decode().rstrip('=')
    labels = [name[i:i+57] for i in range(0, len(name), 57)] + domain.split('.')
    q = struct.pack('!HHHHHH', int.from_bytes(os.urandom(2), 'big'), 0x0100, 1, 0, 0, 0)
    for l in labels:
        q += bytes([len(l)]) + l.encode()
    return q + b'\x00' + struct.pack('!HH', 16, 1)
def addr(port):
    return b'\x04' + bytes([127, 0, 0, 1]) + bytes(12) + struct.pack('!H', port)
sock_path, domain = sys.argv[1], sys.argv[2]
device = b'dev-a\x00\x00\x00'
f = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); f.connect(sock_path)
def send(pkt):
    m = b'NU\x02' + addr(40000) + addr(53) + device + query(pkt, domain)
    f.send(m)
mode = sys.argv[3] if len(sys.argv) > 3 else 'close'
count = int(sys.argv[4]) if len(sys.argv) > 4 else 1
kinds = ['close', 'fail', 'orphan'] if mode == 'all' else [mode]
for m in kinds:
    for _ in range(count):
        d, sc = os.urandom(8), os.urandom(8)
        if m == 'orphan':
            send(initial(d, b'', 0, b'\x01', pad=4) + initial(os.urandom(8), b'', 0, b'\x01', pad=49))
            continue
        send(initial(d, sc, 0, crypto_frame(partial_client_hello())))
        time.sleep(0.05)
        if m == 'close':
            send(initial(d, sc, 1, b'\x1c\x00\x00\x00'))  # CONNECTION_CLOSE(no error, frame 0, no reason)
        elif m == 'fail':
            send(initial(d, sc, 1, b'\x08\x00\x01x'))  # STREAM in an Initial: PROTOCOL_VIOLATION
        else:
            sys.exit('mode: close, fail, orphan or all')
    time.sleep(0.05)
time.sleep(0.5)
print('sent')
