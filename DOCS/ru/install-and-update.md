# Установка и обновление

## Требования

- Роутер **Keenetic** с **Entware** (пакетное окружение `/opt`).
- Opkg-пакеты: `ipset`, `iptables`, `lighttpd`, `lighttpd-mod-cgi`.
- Директория Keenetic `netfilter.d`-hook (`/opt/etc/ndm/netfilter.d`) — есть на
  Keenetic-с-Entware.
- WAN-интерфейс по умолчанию `ppp0` (PPPoE). Для IPoE/DHCP это обычно `eth3` или
  VLAN вида `eth2.2` — задаётся в UI (**Settings → General → WAN interface**),
  хранится в `tacet.conf` и переживает обновления.

```sh
opkg install ipset iptables lighttpd lighttpd-mod-cgi
```

## Установка

На роутере скачайте установщик и запустите — он сам дотянет остальные файлы релиза:

```sh
curl -fsSL https://raw.githubusercontent.com/GrakovNe/tacet/main/install.sh -o /tmp/tacet-install.sh
sh /tmp/tacet-install.sh
```

Он задаёт пару вопросов (порт UI, проброшенные порты для защиты, длительность бана) и по
Enter берёт дефолты. При запуске по headless-SSH без терминала вопросы пропускаются и
установка идёт на дефолтах.

Если `raw.githubusercontent.com` не отвечает (такое бывает), скачайте всё дерево через
codeload и запустите установщик из него:

```sh
curl -fsSL https://codeload.github.com/GrakovNe/tacet/tar.gz/refs/heads/main -o /tmp/tacet.tgz
tar -xzf /tmp/tacet.tgz -C /tmp && sh /tmp/tacet-main/install.sh
```

(Из уже распакованной директории Tacet `sh install.sh` возьмёт файлы на месте.)

`install.sh` выполняет всю настройку и безопасен для повторного запуска:

- раскладывает каждый файл по месту атомарно (работающий скрипт никогда не обрезается на середине копирования);
- добавляет свои две строки в root crontab, не трогая другие записи;
- вписывает LAN-IP в bind-адрес UI;
- применяет firewall-правила и запускает UI и cron.

Version-маркер записывается **последним**, так что прерванный update не помечается
завершённым. На первом запуске движок (`50-tacet.sh`) заполняет whitelist private-
диапазонами RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); дальше файл
считается авторитетным.

Откройте **`http://<LAN-IP-роутера>:5050`** (UI слушает на LAN-IP; порт `5050` по
умолчанию, спрашивается при установке).

### Что куда ложится

| Файл | Устанавливается в | Роль |
|---|---|---|
| `50-tacet.sh` | `/opt/etc/ndm/netfilter.d/50-tacet.sh` | engine (правила + сеты) |
| `tacet-collect.sh` | `/opt/etc/tacet-collect.sh` | per-minute collector |
| `tacet-*-update.sh` | `/opt/etc/` | updaters баз (geo, asn, threat, tor) |
| `tacet-update.sh` | `/opt/etc/tacet-update.sh` | self-updater |
| `tacet-countries` | `/opt/etc/tacet-countries` | таблица country-code → name |
| `index.html`, `api.cgi`, `tacet.css`, `tacet.js` | `/opt/share/tacet/` | web UI |
| `S85tacet-ui`, `S10crond` | `/opt/etc/init.d/` | init-скрипты (UI, cron) |
| `lighttpd-tacet.conf` | `/opt/etc/` | конфиг web-сервера UI |
| `VERSION` | `/opt/etc/tacet-version` | маркер установленной версии |

Runtime-состояние живёт в `/opt/var/` (stats CSV, event log, resolution-кэши, ban-
snapshots) и `/opt/etc/` (`tacet.conf`, `.dat`-базы, `.save`-ban-снапшоты,
`tacet-allow.list`).

## Обновление

Tacet обновляет себя на месте. В UI **Settings → Updates → Check for updates**
спрашивает у GitHub новейший release; если он есть, **Update to vX** скачивает tarball
этого release и запускает его `install.sh --update`. Config, баны и whitelist
сохраняются; базы остаются и повторно скачиваются только при ежедневном auto-update или
ручном refresh.

Из shell то же самое:

```sh
/opt/etc/tacet-update.sh --check    # узнать последний release
/opt/etc/tacet-update.sh --apply    # скачать + установить на месте
```

Повторный запуск `install.sh` из свежего checkout эквивалентен.

## Удаление

Уберите две строки crontab, поставьте `MASTER=no` (или прогоните engine с ним), чтобы
снять все правила, затем удалите `/opt/etc/ndm/netfilter.d/50-tacet.sh`,
`/opt/share/tacet`, `/opt/etc/init.d/S85tacet-ui`, `/opt/etc/lighttpd-tacet.conf`,
`/opt/etc/tacet.conf` (glob `tacet-*` его не захватывает — оставленный файл заставит
позднюю переустановку молча взять старые настройки), `/opt/etc/tacet-*` и
`/opt/var/tacet-*`, и уничтожьте `tacet-*` ipsets. `/opt/etc/init.d/S10crond` — общая
инфраструктура Entware, его не трогайте.
