---
title: Server behind a DNS front
---

# slipstream-server behind a DNS front

The fork's server (branch `server/…`, raycontrol's spec `slipstream-v1`) can take its queries from a DNS front instead
of a UDP socket, and is hardened for queries from anyone.

## Options

| Option | Meaning |
|---|---|
| `--front-socket PATH` | take queries from a DNS front on this unix `SOCK_SEQPACKET` socket, not UDP |
| `--front-uid UID` | required with `--front-socket`: the front's UID; any other peer of the socket is refused |
| `--target-unix PATH` | the target is a unix stream socket, not `--target-address` |
| `--alpn ALPN` | required: the ALPN clients must offer (no shared default: it is in every Initial packet) |
| `--cert`, `--key` | required: no default to the public test key |
| `--idle-timeout S` | seconds a connection may stay silent before it goes (default 120; upstream: never); a handshake has 10 s |
| `--max-connections N` | connections at once (default 64; upstream: 8) |
| `--max-streams N` | streams at once per connection (default 64) |
| `--max-pending-mib N` | bytes queued towards the target, all streams together (default 64 MiB) |
| `--tag-len N` | bytes at the start of each query's data that the front checked (dnsauth-v2: 8) |

## IPC with the front

niko-server's "packet" mode, version 1: the front connects to `--front-socket`, one `SOCK_SEQPACKET` message per query
and per answer, both ways:

```
"NU" | 1 | client (19) | local (19) | DNS message
```

An address is family (4 or 6) | 16 bytes (IPv4 as `::ffff:a.b.c.d`) | port (big-endian). The server copies the two
addresses from a query into its answer: the front answers only a query that waits, within its requester's size. The
socket is created with mode 0660; who reaches it is the directory's business, and the peer's UID is checked with
`SO_PEERCRED`. One front at a time: a new connection replaces the old one.

## What the server answers

- Each query gets at most one answer: the next QUIC packet of its connection, or an empty one.
- Before SPCDNS sees a query, the server checks it and rebuilds it:
  - a header with QR 0 and opcode QUERY;
  - exactly one question of class IN whose name is uncompressed labels of letters, digits, `-` and `_`;
  - at most one OPT record (its options are dropped);
  - nothing after these.
  
  Anything else gets no answer. SPCDNS asserts on malformed input, and upstream such a datagram ended the process.
- The name must end in `--domain`. A name outside it gets REFUSED, another type an empty NOERROR, and bad base32
  SERVFAIL.
- The answer has an OPT record only when the query had one, and then with the query's DO bit.
- Errors of one datagram (decoding, QUIC, encoding, sending) drop that datagram, never the server.
- Version negotiation and stateless reset packets are dropped as they come. Upstream they queued without a bound,
  addressed to the dummy peer.
- Key log: never written. `SSLKEYLOGFILE` is ignored.
- Streams: the client's bidirectional ones only (`--max-streams`); a unidirectional one gets STOP_SENDING, and the
  transport parameters allow one (picoquic reads 0 as no limit).
- The UDP socket does not block: a lone query is answered at once, and SIGTERM ends the loop.
- A path that went away since its query (multipath) is looked up again by its unique ID before the answer.
- Bytes for a target go to its socket at once when nothing waits before them; one connection queues a quarter of
  `--max-pending-mib` at most.

## Checks

`test/server/run.sh build` runs:
- an echo through the tunnel over UDP;
- an echo through a stand-in front, with and without an 8-byte tag;
- hostile and mutated queries, after which the server must still be up;
- a stranger on the front socket, who must be refused;
- `SSLKEYLOGFILE`, which must stay unwritten.
