# Справочник по конфигурации

Каждая настройка хранится в `/opt/etc/tacet.conf` (плоский `KEY=value`-файл, который
читают engine и collector) и правится из **Settings** в UI. Большинство изменений
сохраняются кнопкой **Apply changes**; master switch (dashboard), logging level,
обновления баз и переключатель auto-update применяются мгновенно. Значения по умолчанию ниже — те, что идут в поставке.

## General

| Настройка | Key | Default | Заметки |
|---|---|---|---|
| WAN interface | `WAN` | `ppp0` | Аплинк, за которым следит Tacet. `ppp0` для PPPoE; `eth3` / `eth2.2` для IPoE/DHCP. Смена пересобирает все правила под новый интерфейс. |
| Ban duration | `BAN_TTL` | 24 ч (`86400` с) | Idle timeout — бан снимается через столько после *последней* попытки источника. 1–720 ч. |
| Auto-refresh | `REFRESH_SEC` | 60 с | Как часто UI перезапрашивает. `0` отключает. 5–3600. |
| Color scheme | — | Auto | Auto / Light / Dark, запоминается per-browser (не серверная настройка). |
| Chart scale | — | Log | Log / Linear для графиков dashboard (per-browser). |

## Ban rules

| Настройка | Key | Default | Заметки |
|---|---|---|---|
| Known-bad IPs | `THREAT_BAN` | off | Банить любой адрес из threat-базы сразу, первый пакет, без порога. Нужна threat DB. |
| Tor exit nodes | `TOR_BAN` | off | Банить любой Tor exit relay сразу, тем же механизмом. Нужен Tor list. |
| Closed ports | `TRAP_CLOSED` | on | Closed-port rate trap (INPUT). |
| ↳ Threshold | `BURST` | 8 SYN/min | Ниже — строже; 1–3 может ловить случайный retransmit. |
| Forwarded ports | `TRAP_OPEN` | on | Forwarded-port rate trap (FORWARD). |
| ↳ Protected ports | `SVC_PORTS` | `443` | Проброшенные TCP-порты через запятую; пусто = никакие. |
| ↳ Threshold | `SVC_BURST` | 60 SYN/min | Выше — тут живёт реальный трафик. |
| Subnet size | `SUBNET_MASK` | `/24` | Prefix, по которому два subnet-правила группируют и банят. 8–30; смена пересобирает сеты. |
| Rate-ban blocks | `TRAP_SUBNET` | off | Subnet trap на обеих поверхностях (closed + forwarded), меряется per subnet. |
| ↳ Threshold | `SUBNET_BURST` | 30 SYN/min | Суммарный per-subnet rate; держите выше per-IP лимитов. |
| Fold crowded blocks | `COMPACT` | off | Периодически сворачивать блоки, накопившие много одиночных банов. |
| ↳ Fold at | `COMPACT_PCT` | 5 % | Забаненная доля блока, запускающая fold (плотность, не количество). 1–100. |
| ↳ Check every | `COMPACT_EVERY` | 5 min | Периодичность sweep. 1–1440. |

## Packet dropping

| Настройка | Key | Default | Заметки |
|---|---|---|---|
| Dropping policy | `BAN_REJECT` | Drop | Drop (тихо) или Reject (TCP reset / ICMP unreachable). |
| Half-open timeout | `SYN_TIMEOUT` | 60 с | Ядерный `nf_conntrack_tcp_timeout_syn_sent`: сколько дропнутая/half-open попытка висит. Ниже — быстрее чистит флуды. 10–120. Пусто в файле = оставить system default. |

## Databases

| Настройка | Key | Default | Заметки |
|---|---|---|---|
| GeoIP / Threat / ASN / Tor «Update» | — | — | Скачать/обновить каждую базу по требованию (в фоне). |
| Auto-update | `AUTO_DB_UPDATE` | off | Обновлять все базы раз в 24 ч. |

Есть один collector-only tuning-knob, не вынесенный в UI: **`GEO_EVERY`** (по умолчанию
`5`, минуты) — как часто большие geo/owner-базы резолвятся заново. Задайте в `tacet.conf`,
если хотите, чтобы флаги появлялись быстрее или collector был ещё легче.

## Backup & Restore

Не хранимые настройки — действия. **Backup** скачивает выбранные данные (settings /
whitelist / ban lists) одним JSON-файлом. **Restore** загружает backup в режиме
**append** (добавить записи) или **override** (заменить каждую секцию, что есть в файле).
Каждое значение перепроверяется на роутере перед применением.

## Logging

| Настройка | Keys | Default | Заметки |
|---|---|---|---|
| Logging level | `LOG_ENABLED`, `LOG_DROPS` | Normal | Off / Normal (ban/release/fold события) / Verbose (плюс per-minute drop-счётчики). Свежая установка прописывает `LOG_ENABLED=yes`. |

## Updates

Показ версии и действия Check / Update — см.
[install-and-update.md](install-and-update.md).

---

## Config-файл

`/opt/etc/tacet.conf` — плоский `KEY=value`-файл. Engine (`50-tacet.sh`) и collector оба
его читают, каждый со своими fallback-дефолтами, так что отсутствующий или частичный
файл никогда не ломает rule-build. Правка руками и повторный прогон engine (или
переключение настройки в UI) применяет изменение. Пример:

```sh
BAN_TTL=86400
BURST=8
SVC_PORTS="443,80,8443"
SVC_BURST=45
TRAP_CLOSED=yes
TRAP_OPEN=yes
TRAP_SUBNET=yes
SUBNET_MASK=24
SUBNET_BURST=60
THREAT_BAN=yes
TOR_BAN=no
BAN_REJECT=no
MASTER=yes
SYN_TIMEOUT=60
COMPACT=yes
COMPACT_PCT=3
COMPACT_EVERY=5
AUTO_DB_UPDATE=yes
LOG_ENABLED=yes
LOG_DROPS=no
REFRESH_SEC=10
```

## Управление из shell

Всю систему можно осмотреть и настроить штатными инструментами:

```sh
# посмотреть баны
ipset list tacet-scan
ipset list tacet-flood
ipset list tacet-cnet ; ipset list tacet-fnet

# забанить / разбанить руками (баны попадут в .save-снапшоты на следующем cron-save)
ipset add tacet-scan 203.0.113.10 timeout 86400
ipset del tacet-scan 203.0.113.10

# whitelist
ipset add tacet-allow 203.0.113.0/24
echo "203.0.113.0/24 my note" >> /opt/etc/tacet-allow.list

# пересобрать правила после правки tacet.conf
table=filter type=iptables sh /opt/etc/ndm/netfilter.d/50-tacet.sh

# обновить базу сейчас
sh /opt/etc/tacet-threat-update.sh

# drop-счётчик (кумулятивный с последнего rule-rebuild)
iptables -L INPUT -v -x -n | grep 'match-set tacet'
```

UI опционален. Эндпоинты `api.cgi`, которые он использует: `overview`, `protection`,
`whitelist`, `settings`, `export` (чтения); `master`,
`ban`/`unban`/`white`/`unwhite`/`setnote`, `config`, `loglevel`, `clearlog`,
`geoupdate`/`threatupdate`/`asnupdate`/`torupdate`, `autodb`, `checkupdate`/`doupdate`,
`import` (действия).
