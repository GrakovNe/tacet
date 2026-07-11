# Документация Tacet

**Tacet** — firewall-фронтенд для роутеров Keenetic (Entware). Он следит за
WAN-интерфейсом, авто-банит хосты, которые сканируют закрытые порты или флудят
проброшенные сервисы, и даёт небольшой web-dashboard с флагами стран, network-owner
(ASN) и threat/abuse-атрибуцией для каждого адреса — чтобы всё это видеть и этим управлять.

Название — латинское «оно молчит»: забаненный источник не получает ответа.

- Работает целиком на роутере — без облака, аккаунтов и телеметрии.
- Enforcement — штатные `ipset` + `iptables`; UI — статическая страница плюс shell CGI.
- Все threat/geo-данные скачиваются на роутер и резолвятся локально.

Текущая версия: **1.0.0**.

## Содержание

| Документ | О чём |
|---|---|
| [how-it-works.md](how-it-works.md) | Механизм — traps, баны, правила engine, collector, базы, dropping policy |
| [install-and-update.md](install-and-update.md) | Требования, установка, обновление на месте |
| [configuration.md](configuration.md) | Все настройки, config-файл, CLI, файлы и расположения |
| [validation.md](validation.md) | Security-аудит, нагрузочное тестирование, эффективность в эксплуатации и footprint ресурсов, замерено на роутере |
| [limitations.md](limitations.md) | Что Tacet намеренно НЕ делает, и security-заметки |

## Быстрый старт

На роутере Keenetic с Entware и установленными `ipset`, `iptables`, `lighttpd` +
`lighttpd-mod-cgi`:

```sh
opkg install ipset iptables lighttpd lighttpd-mod-cgi
curl -fsSL https://raw.githubusercontent.com/GrakovNe/tacet/main/install.sh -o /tmp/tacet-install.sh
sh /tmp/tacet-install.sh
```

Затем открыть `http://<LAN-IP-роутера>:5050`. Подробности в
[install-and-update.md](install-and-update.md).

## Как это работает, если коротко

Tacet ставит на WAN четыре механизма защиты:

- **Closed-port trap** — источник, шлющий больше *N* `SYN`/мин на порты, где никто не
  слушает, банится (по умолчанию 8/мин).
- **Forwarded-port trap** — источник, флудящий проброшенный на внутренний сервер порт,
  банится (по умолчанию 60/мин).
- **Subnet trap** *(опционально)* — те же два rate-метра, но агрегированно по `/24`, так что
  botnet, распределённый по диапазону, банится одним блоком.
- **Reputation / Tor rules** *(опционально)* — адреса из скачанного threat-list или
  Tor exit-relay list банятся с первого пакета, без порога.

Забаненный источник попадает в `ipset`, и его пакеты дропаются (или отклоняются, если включён Reject). Раз в
минуту collector пишет статистику, резолвит geo/owner/threat для того, что видит, и
сворачивает переполненные диапазоны. Dashboard, whitelist и настройки — надстройка над
этим механизмом.
