# Как работает Tacet

Tacet состоит из трёх компонентов:

1. **Engine** — `50-tacet.sh`, Keenetic `netfilter.d`-hook, который (пере)собирает все
   правила `iptables` и `ipset`-сеты. Запускается на boot, на каждом firewall-rebuild
   и при любом изменении настройки.
2. **Collector** — `tacet-collect.sh`, запускается раз в минуту из cron. Пишет
   статистику, резолвит geo/owner/threat для видимых адресов, сворачивает переполненные
   subnet, ведёт event log.
3. **UI** — статические `index.html` + `tacet.js`, отдаются отдельным `lighttpd`,
   говорят с `api.cgi` (shell CGI) по JSON. UI только отображает; enforcement он не делает.

Enforcement — целиком `ipset` + `iptables`. UI можно остановить, и Tacet продолжит
защищать.

## Ban-сеты

Каждый бан — членство в одном из **четырёх** ban-`ipset`. Ещё два — *reference*-сеты
(threat- и Tor-списки): их проверяют first-packet-правила, но баны они не держат. Все
шесть:

| Set | Тип | Что держит |
|---|---|---|
| `tacet-scan` | `hash:ip` | одиночные IP на закрытых портах (CIDR-бан руками уходит в `tacet-cnet`) |
| `tacet-flood` | `hash:ip` | одиночные IP на проброшенных портах (CIDR-бан руками уходит в `tacet-fnet`) |
| `tacet-cnet` | `hash:ip` + netmask | целые `/SUBNET_MASK` блоки, closed-port abuse |
| `tacet-fnet` | `hash:ip` + netmask | целые `/SUBNET_MASK` блоки, forwarded-port abuse |
| `tacet-threat` | `hash:ip` | скачанный threat-list (*reference*-сет, не баны) |
| `tacet-tor` | `hash:ip` | скачанный Tor exit-relay list (reference-сет) |

Плюс `tacet-allow` (`hash:net`) — whitelist, проверяется раньше всего.

## Traps (как источник получает бан)

Все traps используют `xt_hashlimit` — ядерный per-source rate-метр. Каждый — одно
`iptables`-правило, чей `-j SET --add-set` добавляет нарушителя в ban-сет, как только
он превышает rate. Порог зашит в имя метра, так что смена порога начинает новый счёт.

### Closed-port trap (`TRAP_CLOSED`, на `INPUT`)

`SYN` на порт роутера, где никто не слушает, по определению незапрошен. Источник,
шлющий больше **`BURST`** (по умолчанию 8) `SYN`/мин на такие порты, добавляется в
`tacet-scan`. Это типичный случай: фоновые сканеры непрерывно перебирают закрытые
порты.

### Forwarded-port trap (`TRAP_OPEN`, на `FORWARD`)

Для каждого порта из **`SVC_PORTS`** (порты, проброшенные на внутренний сервер),
источник, шлющий больше **`SVC_BURST`** (по умолчанию 60) `SYN`/мин, добавляется в
`tacet-flood`. Порог выше, потому что тут живёт реальный трафик — 60/мин останавливает
флуд, не мешая браузеру.

### Subnet trap (`TRAP_SUBNET`, опционально, по умолчанию off)

Те же два rate-метра, но по ключу `/SUBNET_MASK` (по умолчанию `/24`), а не по
одиночному адресу. Abuse, распределённый по диапазону (каждый адрес под per-IP порогом),
объединяется в один общий bucket; когда суммарный rate превышает **`SUBNET_BURST`** (по умолчанию
30/мин), весь блок банится одной записью (`tacet-cnet` для closed, `tacet-fnet` для
forwarded). Off по умолчанию, потому что бан целых блоков — намеренный collateral;
включайте, когда botnet ротирует адреса внутри одного диапазона.

### Reputation и Tor rules (`THREAT_BAN` / `TOR_BAN`, опционально, по умолчанию off)

Эти не меряют rate — банят с **первого пакета**. Правило срабатывает на любой источник в
reference-сете `tacet-threat` (или `tacet-tor`) и добавляет его сразу в ban-сет. Его
первый `SYN` дропается, и он забанен на полную длительность, без порога. Выключение
фичи освобождает reference-сет. Threat-сет берётся из скачанных баз (см. ниже).

## Drop (что делает бан)

Для каждого из четырёх ban-сетов `INPUT` и `FORWARD` несут два правила:

1. **Refresh**-правило (`-j SET --add-set … --exist`), которое обновляет timeout
   бана на каждом пакете от забаненного источника.
2. **Drop**-правило, которое отбрасывает пакет.

Порядок важен. Поскольку refresh идёт первым, **бан — sticky idle timeout**: держится
`BAN_TTL` (по умолчанию 24 ч) с *последней* попытки, а не с первой. Упорный источник
остаётся заблокированным; бан снимается лишь через 24 ч после последней попытки.

`INPUT` drop исключает `ESTABLISHED`/`RELATED`, так что бан не разрывает активную
сессию *к самому роутеру* (ваши tunnels сохраняются); разрываются только новые
соединения. Forwarded-потоки разрываются сразу.

### Dropping policy (`BAN_REJECT`)

- **Drop** (по умолчанию) — пакет тихо отбрасывается, источник не получает ответа и
  шлёт retransmit, пока его собственный TCP-стек не закроет попытку по таймауту.
- **Reject** — роутер отвечает забаненному TCP-источнику `tcp-reset` (а всему
  остальному — ICMP port-unreachable). Это быстрее прекращает поток retransmit'ов, но
  подтверждает, что по этому адресу есть хост. Drop — более безопасный default.

## Master switch (`MASTER`)

`MASTER=no` заставляет engine убрать **все** правила Tacet — защита полностью off — при
этом ban-сеты остаются целыми. Включение обратно пересобирает каждое правило;
существующие баны всё ещё в сетах, так что снова действуют немедленно.

## Sticky-баны и persistence

Баны переживают reboot. Cron-задача сохраняет четыре ban-сета в `/opt/etc/*.save`
каждые 30 минут (во временный файл, swap только если `ipset save` реально выдал сет —
присутствует его `create`-строка — так что save на раннем boot, до создания сетов, не
затрёт хороший snapshot, а намеренно очищенный сет при этом сохраняется). На boot engine
восстанавливает их, если живой сет пуст. Намеренная очистка (unban-all, override при
restore) обновляет snapshot немедленно — следующий rebuild или reboot не воскресит
только что снятое; snapshot, снятый под другим `SUBNET_MASK`, отбрасывается, а не
пере-маскируется в чужие блоки.

## Collector (раз в минуту)

`tacet-collect.sh` делает всю не-enforcement работу:

- **Stats** — дописывает `epoch,closed,open,dropped,cnet,fnet` в CSV (хранится ~25 ч)
  для графиков dashboard. Dropped-счётчик — точный кумулятивный `iptables -x`-счётчик
  (графики выводят из него поминутную дельту).
- **Resolution** — для каждого сейчас видимого адреса (забаненного, whitelisted или в
  connection table) резолвит country, network owner, threat score и abuse-категорию из
  локальных баз и кэширует результат. Дешёвый threat/activity lookup идёт каждую минуту
  (формирует красный badge); две большие базы — geo (355k ranges) и owner/ASN (398k
  ranges) — резолвятся с периодичностью **`GEO_EVERY` минут** (по умолчанию 5), потому что
  флаг страны, появившийся на пару минут позже, ничего не стоит, а сам бан немедленный.
  Резолвер — merge-join, который потоково читает каждую базу один раз, держа лишь
  несколько MB RAM.
- **Compaction** (`COMPACT`, опционально) — каждые `COMPACT_EVERY` минут проходит по
  ban-list и сворачивает любой `/SUBNET_MASK` блок, который тихо накопил много
  single-IP банов (когда **`COMPACT_PCT`** % блока забанено), в один subnet-бан. Ловит
  медленный abuse, который пропускает rate-trap: botnet, чьи адреса обращаются редко,
  не превышает per-minute порог, но накапливает десятки одиночных банов в одном блоке за
  часы. Сворачивание сжимает list и блокирует остаток диапазона заранее.
- **Event log** (`LOG_ENABLED`) — пишет ban/release/fold/config события, диффая сеты
  против snapshot. Mass-ban burst (тысячи новых банов за минуту) логируется одной
  summary-строкой вместо записи на каждый.

## Базы

Пять локальных баз (их поддерживают четыре update-задачи — threat-задача строит и
threat-, и activity-список), обновляются по требованию или ежедневным auto-update
(`AUTO_DB_UPDATE`). Все бесплатные, без ключей, скачиваются на роутер:

| База | Источник | Файл | Отвечает за |
|---|---|---|---|
| **Geo** (IP→country) | dbip-country через jsDelivr | `tacet-geo.dat` (~8 MB) | флаги стран |
| **Owner / ASN** | dbip-asn через jsDelivr | `tacet-asn.dat` (~20 MB) | строку network-owner |
| **Threat** | IPsum (30+ abuse-feeds), confidence ≥3 списка | `tacet-threat.dat` (~0.4 MB) | красный `!` badge + reputation auto-ban |
| **Activity** | blocklist.de per-service, CINS, GreenSnow, Feodo Tracker | `tacet-activity.dat` (~0.9 MB) | *что* адрес делал (port-scan, brute-force, mail, web, VoIP, botnet C2) |
| **Tor exit list** | torproject.org bulk exit list (fallback на FireHOL mirror) | `tacet-tor.dat` (~30 KB) | Tor auto-ban rule |

Базы хранят integer-IP-ranges, отсортированные для binary-search / merge-join
резолвера. Geo и ASN приходят предсортированными из источника; threat/Tor/activity
сортируются на роутере фиксированной-ширины ключом (busybox `sort -n` переполняется
выше 2³¹, поэтому сортировка использует zero-padded лексический ключ).
