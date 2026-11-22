# arngory/slipstream

A fork of [EndPositive/slipstream](https://github.com/EndPositive/slipstream), the covert channel over DNS on QUIC
multipath, for a [raycontrol](https://github.com/arngory/raycontrol) node and the
[Niko](https://github.com/arngory/niko) client (raycontrol `docs/spec/slipstream-v1.md`). Two branches grow from upstream `main` (`e158a68`), one for each
side; `main` stays upstream's.

## Branches

| Branch | Side | What differs from upstream |
|---|---|---|
| **`server/hardening`** | raycontrol (the server) | the server hardened for queries from anyone, behind niko-server's DNS front (it names the device); copies of packets and abandoned paths kept in bounds; a limit of connections per device (`--max-connections-per-device`); a static build (Alpine, musl, OpenSSL linked in) for amd64 and arm64; releases `server-vX.Y.Z` with `SHA256SUMS` |
| `client/pin-alpn-sni` | Niko (the client) | the client Niko embeds: the server's key by its pin, ALPN and SNI from the arguments, no key log; streams ended by their FIN; dnsauth-v2 in every query; idle and handshake timeouts; a fixed receive window of 256 KiB; zones up to 134 characters (packets down to 64 bytes); the Android build (4 ABIs, OpenSSL static); CI against the server (this tree's until the first release on the new picoquic, then the release) |

Both build picoquic from [arngory/picoquic](https://github.com/arngory/picoquic), branch `slipstream` (upstream
picoquic and the slipstream series; what each patch changes and why is in its `FORK.md`), not from
EndPositive/slipstream-picoquic: the server from `server/picoquic-port` on, the client since it merged that branch. The enforced initial MTU is a
build option (`enforced_initial_mtu`, 64 by default) and must match picoquic's, or the link fails. Multipath moved to
draft-20 there: a new client does not work with an older server, so the server is released first.

Each side's branch is its own: a change to the server goes to `server/hardening`, a change to the client to
`client/pin-alpn-sni`.

## Who pins it

| Where | Pin |
|---|---|
| raycontrol `deploy/versions.env` | `SLIPSTREAM_SERVER_TAG=server-v0.2.0` (`dc5f41d`) and the SHA-256 of both servers; `SLIPSTREAM_CLIENT_COMMIT=4c7c01a` on `client/pin-alpn-sni`, for raycontrol's CI only |
| Niko `.github/slipstream-server.env` | `server-v0.2.0` and the SHA-256 of its amd64 server |

Neither branch is rewritten, and no `server-v*` tag is moved or deleted: a pin on a commit or a release that is gone
no longer builds.

## Working on it

- A server change goes to `server/hardening` by a pull request from a branch of its own, with a test in
  `test/server/`; the Server workflow (`server.yml`) builds the static servers and runs `test/server/run.sh` on each
  push to `server/**`.
- A server release: the tag `server-vX.Y.Z`, or Actions → Server → Run workflow with the tag to make. It publishes the
  two servers and `SHA256SUMS`, and raycontrol pins the tag, commit and hashes.
- Checks (`.github/workflows/checks.yml`): "Commit messages" (no bare `#N`; in a fork GitHub links a bare `#N` to
  upstream's issues, so write `arngory/slipstream#N`) and "Secrets" (gitleaks, rules in `.gitleaks.toml`). Both take
  only the pull request's own line, not upstream's commits: upstream's test certificate in `certs/` is upstream's.
- A pull request that changes the checks themselves is merged by the owner.
- The rules shared with raycontrol, niko-server and Niko: raycontrol's
  [CONTRIBUTING.md](https://github.com/arngory/raycontrol/blob/main/CONTRIBUTING.md).
