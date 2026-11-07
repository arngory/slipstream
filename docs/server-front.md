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
| `--max-connections-per-device N` | connections at once of one device, as the front names it (IPC version 2): over it, the device's connection silent longest goes if silent 5 s (or half a shorter `--idle-timeout`; a client's keepalives come every 400 ms), else the new one does (default 0: no limit; at most `--max-connections`) |

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

A front that checked the query's device tag (niko-server v0.14.0, `devices` on the backend) names the device in
version 2, the answers staying in version 1:

```
"NU" | 2 | client (19) | local (19) | device (8) | DNS message
```

The device is a token of the front's (a hash of the device's ID), the same for all its queries. The first packet
picoquic takes for a new connection decides, once, the device it holds a place of (none when that packet came in
version 1); `--max-connections-per-device` counts by it. A connection closed before (a CONNECTION_CLOSE in its
handshake) holds no place.
Without it (version 1, or UDP) a connection has no device and no such limit: one device's key could otherwise take
every connection of the server, the others' waiting out the idle timeout.

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
- The answer has an OPT record only when the query had one, and then with the query's DO bit and a size of 4096, the
  size every answer of a raycontrol node says (the front's own, dnstt's). Names of up to 253 characters are taken.
- Errors of one datagram (decoding, QUIC, encoding, sending) drop that datagram, never the server.
- Version negotiation and stateless reset packets are dropped as they come. Upstream they queued without a bound,
  addressed to the dummy peer.
- Key log: never written. `SSLKEYLOGFILE` is ignored.
- Copies of a packet: a query is bound to a connection, and gets its next packet, only when picoquic took the
  query's packet as new. A copy (anyone on the path can resend a query, from any address) or a packet that does not
  open names the connection all the same; it is answered empty. picoquic does not always know a copy: once the peer
  has acknowledged an ACK, the highest range of received numbers starts after it, and what was cut off counts as
  never received. So the server remembers the packets picoquic took, by a hash of their bytes, for 30 to 60 s (two
  generations of 2^18 slots, 4 MiB; a full one turns early), and a copy goes no further. Beyond that, every 1-RTT
  ACK context keeps an ACK horizon (10 s, raised to the lowest range kept): what lies below it counts as received.
  A packet older than the horizon that was never received is dropped; QUIC sends its frames again. In front mode
  the front refuses copies for as long as their tag holds. Left open: a peer that gets ~2^17 packets taken twice
  within 10 s (~26 000 a second) turns the memory early, and copies of the numbers picoquic cut off may pass in
  UDP mode; a copy that reaches the server before the original takes its answer.
- Streams: the client's bidirectional ones only (`--max-streams`). The client opens no other: a unidirectional
  stream closes the connection (refused one by one, their records stayed until it ended). The transport
  parameters allow one (picoquic reads 0 as no limit).
- The UDP socket does not block: a lone query is answered at once, and SIGTERM ends the loop.
- Paths (multipath): a path that went away since its query is looked up again by its unique ID before the answer;
  one abandoned since, about to be (a failed challenge), or still without the peer's connection ID, is not used: the
  first path that is fit is named. Abandoned paths are deleted before any slot's answer. A connection with every path abandoned goes (prepare would take a path
  without a connection ID, or none, and crash); a connection with none left is reaped.
- Bytes for a target go to its socket at once when nothing waits before them. One connection queues
  `--max-pending-mib` over `--max-connections` at most, 4 MiB (four streams' limit) at least.
- Descriptors: a target socket per stream, and a connection may have about 1.5 times `--max-streams` at once
  (picoquic opens the next ones before the closed ones go). The soft limit goes up to the hard one; below
  `--max-connections` × `--max-streams` × 1.5 + 64 the server warns (raise LimitNOFILE). Out of descriptors,
  accepting a front pauses 100 ms; the rest goes on.

## Checks

`test/server/run.sh build` runs:
- an echo through the tunnel over UDP;
- an echo with a copy of every query sent from another address once answered, and again 2 s later (`replay.py`):
  every copy must be answered empty;
- an echo through a stand-in front, with and without an 8-byte tag;
- hostile and mutated queries, after which the server must still be up;
- a stranger on the front socket, who must be refused;
- `SSLKEYLOGFILE`, which must stay unwritten.
