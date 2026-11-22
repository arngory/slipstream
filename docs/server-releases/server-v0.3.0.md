slipstream-server on picoquic from arngory/picoquic, branch `slipstream` (`3743026`: upstream tag `92fa226` and the slipstream series, three review rounds; arngory/picoquic#1), instead of EndPositive/slipstream-picoquic `2ee2ecd` (upstream of 2024-11-25).

- Initials down to 64 bytes (the enforced initial MTU, 129 before). An Initial shorter than 129 bytes was dropped, so a zone longer than about 29 characters did not work; with this server and a client on the same picoquic a zone may be up to 134 characters with dnsauth-v2 and 148 without (raycontrol docs/spec/dns-zone-length-v1.md). The value is a build option (`enforced_initial_mtu`) and must match picoquic's, or the link fails.
- A Version Negotiation is built only by a server and only when both connection IDs of the packet lie inside it. The old picoquic, at its lowered floor, read up to 453 bytes past a 64-byte datagram for an unknown version and could send them back (B1 of the fork's review).
- A fixed receive window of 256 KiB per connection and per stream: the memory a connection holds for data it receives is bounded (about 17.5 MB at most), and does not grow with what a client sends.
- Multipath moved from draft-11 to draft-20 code points. Clients on the old picoquic (Niko up to now) work with this server as before; a client on the new picoquic needs this server. Update the server first.
- Checked by test/server/run.sh on the static servers (amd64, arm64), all sections; a client on the old picoquic echoes 200 KB and 2 MB through this server. picoquic's own tests: the same 15 failures as the plain upstream tag (the socket tests of a sandbox), and those its deliberate changes for small packets account for (picoquic's FORK.md).

---

slipstream-server на picoquic из arngory/picoquic, ветка `slipstream` (`3743026`: upstream-тег `92fa226` и серия slipstream, три раунда ревью; arngory/picoquic#1), вместо EndPositive/slipstream-picoquic `2ee2ecd` (upstream от 2024-11-25).

- Initial от 64 байт (enforced initial MTU, было 129). Initial короче 129 байт отбрасывался, и зона длиннее примерно 29 символов не работала; с этим сервером и клиентом на том же picoquic зона может быть до 134 символов с dnsauth-v2 и до 148 без него (raycontrol docs/spec/dns-zone-length-v1.md). Значение — опция сборки (`enforced_initial_mtu`), оно должно совпадать с picoquic, иначе не соберётся.
- Version Negotiation строит только сервер и только если оба ID соединения пакета лежат внутри него. Старый picoquic при пониженном пороге на неизвестной версии читал до 453 байт за концом 64-байтной датаграммы и мог отправить их обратно (B1 ревью форка).
- Окно приёма фиксировано: 256 КиБ на соединение и на поток. Память, которую соединение держит под принятые данные, ограничена (не больше примерно 17,5 МБ) и не растёт от того, сколько шлёт клиент.
- Multipath перешёл с draft-11 на draft-20. Клиенты на старом picoquic (Niko до сих пор) работают с этим сервером как раньше; клиенту на новом picoquic нужен этот сервер. Обновлять сначала сервер.
- Проверено test/server/run.sh на статических серверах (amd64, arm64), все разделы; клиент на старом picoquic прокачивает через этот сервер 200 КБ и 2 МБ эха. Собственные тесты picoquic: те же 15 падений, что у чистого upstream-тега (сокетные тесты песочницы), и те, что объясняются его намеренными изменениями для маленьких пакетов (FORK.md picoquic).
