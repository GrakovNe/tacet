# Configuration reference

Every setting is stored in `/opt/etc/tacet.conf` (a plain `KEY=value` file sourced by
the engine and collector) and edited from **Settings** in the UI. Most changes save
with **Apply changes**; the master switch (dashboard), the logging level, the database
updates and the auto-update toggle apply instantly. Defaults below are the shipped values.

## General

| Setting | Key | Default | Notes |
|---|---|---|---|
| WAN interface | `WAN` | `ppp0` | The uplink Tacet watches. `ppp0` for PPPoE; `eth3` / `eth2.2` for IPoE/DHCP. Changing it rebuilds every rule against the new interface. |
| Ban duration | `BAN_TTL` | 24 h (`86400` s) | Idle timeout — a ban lapses this long after the source's *last* attempt. 1–720 h. |
| Auto-refresh | `REFRESH_SEC` | 60 s | How often the UI re-fetches. `0` disables. 5–3600. |
| Color scheme | — | Auto | Auto / Light / Dark, remembered per-browser (not a server setting). |
| Chart scale | — | Log | Log / Linear for the dashboard charts (per-browser). |

## Ban rules

| Setting | Key | Default | Notes |
|---|---|---|---|
| Known-bad IPs | `THREAT_BAN` | off | Ban any address on the threat database outright, first packet, no threshold. Needs the threat DB. |
| Tor exit nodes | `TOR_BAN` | off | Ban any Tor exit relay outright, same machinery. Needs the Tor list. |
| Closed ports | `TRAP_CLOSED` | on | The closed-port rate trap (INPUT). |
| ↳ Threshold | `BURST` | 8 SYN/min | Lower is stricter; 1–3 may catch a stray retransmit. |
| Forwarded ports | `TRAP_OPEN` | on | The forwarded-port rate trap (FORWARD). |
| ↳ Protected ports | `SVC_PORTS` | `443` | Comma-separated forwarded TCP ports to guard; empty = none. |
| ↳ Threshold | `SVC_BURST` | 60 SYN/min | Higher — real traffic lives here. |
| Subnet size | `SUBNET_MASK` | `/24` | Prefix length the two subnet rules aggregate and ban on. 8–30; changing it rebuilds the sets. |
| Rate-ban blocks | `TRAP_SUBNET` | off | Subnet trap on both surfaces (closed + forwarded), metered per subnet. |
| ↳ Threshold | `SUBNET_BURST` | 30 SYN/min | Combined per-subnet rate; keep above the per-IP limits. |
| Fold crowded blocks | `COMPACT` | off | Periodically fold blocks that accumulated many single bans. |
| ↳ Fold at | `COMPACT_PCT` | 5 % | Banned share of a block that triggers a fold (density, not count). 1–100. |
| ↳ Check every | `COMPACT_EVERY` | 5 min | Sweep cadence. 1–1440. |

## Packet dropping

| Setting | Key | Default | Notes |
|---|---|---|---|
| Dropping policy | `BAN_REJECT` | Drop | Drop (silent) or Reject (TCP reset / ICMP unreachable). |
| Half-open timeout | `SYN_TIMEOUT` | 60 s | Kernel `nf_conntrack_tcp_timeout_syn_sent`: how long a dropped/half-open attempt lingers. Lower clears floods faster. 10–120. Empty in the file leaves the system default. |

## Databases

| Setting | Key | Default | Notes |
|---|---|---|---|
| GeoIP / Threat / ASN / Tor "Update" | — | — | Download or refresh each database on demand (background). |
| Auto-update | `AUTO_DB_UPDATE` | off | Refresh all databases once every 24 h. |

There is one collector-only tuning knob not exposed in the UI: **`GEO_EVERY`**
(default `5`, minutes) — how often the big geo/owner databases re-resolve. Set it in
`tacet.conf` if you want flags to appear sooner or the collector to be even lighter.

## Backup & Restore

Not stored settings — actions. **Backup** downloads the selected data (settings /
whitelist / ban lists) as one JSON file. **Restore** loads a backup in **append**
(add entries) or **override** (replace each section the file carries) mode. Every
value is re-validated on the router before it is applied.

## Logging

| Setting | Keys | Default | Notes |
|---|---|---|---|
| Logging level | `LOG_ENABLED`, `LOG_DROPS` | Normal | Off / Normal (ban/release/fold events) / Verbose (also per-minute drop counts). A fresh install seeds `LOG_ENABLED=yes`. |

## Updates

Version display and the Check / Update actions — see
[install-and-update.md](install-and-update.md).

---

## The config file

`/opt/etc/tacet.conf` is a flat `KEY=value` file. The engine (`50-tacet.sh`) and
collector both source it, each carrying its own fallback defaults so a missing or
partial file never breaks a rule build. Editing it by hand and re-running the engine
(or toggling a setting in the UI) applies the change. Example:

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

## Operating from the shell

The whole system is inspectable and controllable with stock tools:

```sh
# see the bans
ipset list tacet-scan
ipset list tacet-flood
ipset list tacet-cnet ; ipset list tacet-fnet

# ban / unban by hand (bans persist to the .save snapshots on the next cron save)
ipset add tacet-scan 203.0.113.10 timeout 86400
ipset del tacet-scan 203.0.113.10

# whitelist
ipset add tacet-allow 203.0.113.0/24
echo "203.0.113.0/24 my note" >> /opt/etc/tacet-allow.list

# rebuild the rules after editing tacet.conf
table=filter type=iptables sh /opt/etc/ndm/netfilter.d/50-tacet.sh

# refresh a database now
sh /opt/etc/tacet-threat-update.sh

# the drop counter (cumulative since the last rules rebuild)
iptables -L INPUT -v -x -n | grep 'match-set tacet'
```

The UI is optional. The `api.cgi` endpoints it uses are: `overview`, `protection`,
`whitelist`, `settings`, `export` (reads); `master`,
`ban`/`unban`/`white`/`unwhite`/`setnote`, `config`, `loglevel`, `clearlog`,
`geoupdate`/`threatupdate`/`asnupdate`/`torupdate`, `autodb`, `checkupdate`/`doupdate`,
`import` (actions).
