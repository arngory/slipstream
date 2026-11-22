The slipstream server as raycontrol ships it (raycontrol docs/spec/slipstream-v1.md): static for linux amd64 and arm64 (Alpine, musl, OpenSSL linked in), hardened for queries from anyone and taking them from niko-server's DNS front. What changed from upstream and why: docs/server-front.md.

- A datagram never ends the process: SPCDNS gets only a query rebuilt after a check of its own; errors drop one datagram.
- Limits: idle timeout (120 s), handshake 10 s, connections (64), streams per connection (64), bytes queued towards the target (64 MiB, a connection's share), descriptors raised to the hard limit.
- No shared marks: `--alpn`, `--cert` and `--key` are required; no key log.
- `--front-socket` and `--front-uid`: queries from the DNS front over a unix SOCK_SEQPACKET socket (IPC v1), its UID checked; `--tag-len 8` skips the dnsauth-v2 field the front checked. `--target-unix`: the inner stage over a unix socket.
- Copies of a query (anyone on the path, from any address) get an empty answer: a query is bound to a connection only when picoquic took its packet as new; the server remembers the packets it took 30-60 s and keeps an ACK horizon for the older.
- Multipath: a path abandoned since its query is not used, a connection with every path abandoned goes (a client with two resolvers could end the process); a unidirectional stream closes the connection.
- Answers: an OPT of 4096 with the query's DO bit when the query had one; names of 253 characters.

Checked by test/server/run.sh against a client of the same tree: echo over UDP and through a stand-in front (with and without a tag), hostile and mutated queries, copies at once and 2 s later, a stranger on the front socket, no key log.

---

Сервер slipstream в том виде, в каком его ставит raycontrol (raycontrol docs/spec/slipstream-v1.md): статический для linux amd64 и arm64 (Alpine, musl, OpenSSL внутри), закалённый для запросов от кого угодно и принимающий их от DNS-фронта niko-server. Что изменено по сравнению с upstream и зачем — docs/server-front.md.

- Датаграмма никогда не роняет процесс: SPCDNS получает только запрос, пересобранный после собственной проверки; ошибки отбрасывают одну датаграмму.
- Пределы: простой (120 с), рукопожатие 10 с, соединения (64), потоки на соединение (64), очередь к цели (64 МиБ, доля соединения), дескрипторы — до жёсткого предела.
- Без общих примет: `--alpn`, `--cert` и `--key` обязательны; key log не пишется.
- `--front-socket` и `--front-uid`: запросы от DNS-фронта по unix SOCK_SEQPACKET (IPC v1) с проверкой UID; `--tag-len 8` пропускает поле dnsauth-v2, которое проверил фронт. `--target-unix`: внутренняя ступень по unix-сокету.
- Копии запроса (любой на пути, с любого адреса) получают пустой ответ: запрос привязывается к соединению, только если picoquic взял его пакет как новый; сервер помнит взятые пакеты 30–60 с и держит горизонт ACK для более старых.
- Multipath: путь, брошенный после запроса, не используется; соединение, у которого брошены все пути, уходит (клиент с двумя резолверами мог уронить процесс); однонаправленный поток закрывает соединение.
- Ответы: OPT 4096 с битом DO запроса, если он был в запросе; имена до 253 символов.

Проверено test/server/run.sh против клиента из того же дерева: эхо по UDP и через эмулятор фронта (с меткой и без), враждебные и искажённые запросы, копии сразу и через 2 с, чужой на сокете фронта, key log пуст.
