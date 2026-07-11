# Install and update

## Requirements

- A **Keenetic** router with **Entware** (the `/opt` package environment).
- Opkg packages: `ipset`, `iptables`, `lighttpd`, `lighttpd-mod-cgi`.
- The Keenetic `netfilter.d` hook directory (`/opt/etc/ndm/netfilter.d`) — present on
  Keenetic-with-Entware setups.
- The WAN interface defaults to `ppp0` (PPPoE). For IPoE/DHCP uplinks it is usually
  `eth3` or a VLAN like `eth2.2` — set it in the UI (**Settings → General → WAN
  interface**); it is stored in `tacet.conf` and survives updates.

```sh
opkg install ipset iptables lighttpd lighttpd-mod-cgi
```

## Install

On the router, download the installer and run it — it fetches the rest of the release
itself:

```sh
curl -fsSL https://raw.githubusercontent.com/GrakovNe/tacet/main/install.sh -o /tmp/tacet-install.sh
sh /tmp/tacet-install.sh
```

It asks a few questions (UI port, forwarded ports to protect, ban duration) and accepts
the defaults on Enter. Run over a headless SSH session with no terminal, it skips the
questions and installs with the defaults.

If `raw.githubusercontent.com` times out (it occasionally does), fetch the whole tree
from codeload instead and run the installer from it:

```sh
curl -fsSL https://codeload.github.com/GrakovNe/tacet/tar.gz/refs/heads/main -o /tmp/tacet.tgz
tar -xzf /tmp/tacet.tgz -C /tmp && sh /tmp/tacet-main/install.sh
```

(From an already-unpacked Tacet directory, `sh install.sh` uses those files directly.)

`install.sh` sets everything up and is safe to re-run:

- copies each file into place atomically (a running script is never truncated mid-copy);
- merges its two lines into the root crontab without touching other entries;
- writes the LAN IP into the UI's bind address;
- applies the firewall rules and starts the UI and cron.

The version marker is written **last**, so a failed update is not marked complete. On
its first run the engine (`50-tacet.sh`) seeds the whitelist with the RFC 1918 private
ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); after that the file is
authoritative.

Open **`http://<router-LAN-IP>:5050`** (the UI binds to the LAN IP; the port defaults
to `5050` and is asked during install).

### What lands where

| File | Installed to | Role |
|---|---|---|
| `50-tacet.sh` | `/opt/etc/ndm/netfilter.d/50-tacet.sh` | the engine (rules + sets) |
| `tacet-collect.sh` | `/opt/etc/tacet-collect.sh` | per-minute collector |
| `tacet-*-update.sh` | `/opt/etc/` | database updaters (geo, asn, threat, tor) |
| `tacet-update.sh` | `/opt/etc/tacet-update.sh` | self-updater |
| `tacet-countries` | `/opt/etc/tacet-countries` | country-code → name table |
| `index.html`, `api.cgi`, `tacet.css`, `tacet.js` | `/opt/share/tacet/` | the web UI |
| `S85tacet-ui`, `S10crond` | `/opt/etc/init.d/` | init scripts (UI, cron) |
| `lighttpd-tacet.conf` | `/opt/etc/` | UI web-server config |
| `VERSION` | `/opt/etc/tacet-version` | installed-version marker |

Runtime state lives in `/opt/var/` (stats CSV, event log, resolution caches, ban
snapshots) and `/opt/etc/` (`tacet.conf`, the `.dat` databases, the `.save` ban
snapshots, `tacet-allow.list`).

## Update

Tacet updates itself in place. In the UI, **Settings → Updates → Check for updates**
asks GitHub for the newest release; if one exists, **Update to vX** downloads that
release's tarball and runs its `install.sh --update`. Config, bans and the whitelist
are all preserved; the databases are kept and only re-downloaded on the daily
auto-update or a manual refresh.

From the shell, the same thing:

```sh
/opt/etc/tacet-update.sh --check    # discover the latest release
/opt/etc/tacet-update.sh --apply    # download + install it in place
```

Re-running `install.sh` from a fresh checkout is equivalent.

## Uninstall

Remove the two crontab lines, set `MASTER=no` (or run the engine once with it) to
drop all rules, then delete `/opt/etc/ndm/netfilter.d/50-tacet.sh`, `/opt/share/tacet`,
`/opt/etc/init.d/S85tacet-ui`, `/opt/etc/lighttpd-tacet.conf`, `/opt/etc/tacet.conf`
(the `tacet-*` glob misses it — leaving it makes a later reinstall silently reuse the
old settings), `/opt/etc/tacet-*` and `/opt/var/tacet-*`, and destroy the `tacet-*`
ipsets. `/opt/etc/init.d/S10crond` is shared Entware infrastructure — leave it.
