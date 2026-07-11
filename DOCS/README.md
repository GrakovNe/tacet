# Tacet documentation

**Tacet** is a firewall front-end for Keenetic routers (Entware). It watches the WAN
interface, auto-bans hosts that scan closed ports or flood forwarded services, and
gives you a small web dashboard to see and manage it, with country flags,
network-owner and threat/abuse attribution for every address.

The name is Latin for *"it is silent"*: a banned source gets no reply.

- Runs entirely on the router — no cloud, no accounts, no telemetry.
- Enforcement is stock `ipset` + `iptables`; the UI is a static page plus a shell CGI.
- All threat/geo data is downloaded to the router and resolved locally.

Current version: **1.0.0**.

## Contents

| Doc | What's in it |
|---|---|
| [how-it-works.md](how-it-works.md) | The mechanism — traps, bans, the engine rules, the collector, the databases, the dropping policy |
| [install-and-update.md](install-and-update.md) | Requirements, install, in-place updates |
| [configuration.md](configuration.md) | Every setting, the config file, the CLI, files and locations |
| [validation.md](validation.md) | Security audit, load testing, production effectiveness and the resource footprint, measured on the router |
| [limitations.md](limitations.md) | What it deliberately does not do, and security notes |

## Quick start

On a Keenetic router with Entware and `ipset`, `iptables`, `lighttpd` +
`lighttpd-mod-cgi` installed:

```sh
opkg install ipset iptables lighttpd lighttpd-mod-cgi
curl -fsSL https://raw.githubusercontent.com/GrakovNe/tacet/main/install.sh -o /tmp/tacet-install.sh
sh /tmp/tacet-install.sh
```

Then open `http://<router-LAN-IP>:5050`. Full detail in
[install-and-update.md](install-and-update.md).

## The short version of how it works

Tacet installs four defenses on the WAN:

- **Closed-port trap** — a source sending more than *N* `SYN`/min to ports nothing
  listens on gets banned (default 8/min).
- **Forwarded-port trap** — a source flooding a port you forward to an internal
  server gets banned (default 60/min).
- **Subnet trap** *(optional)* — the same two meters, but aggregated per `/24`, so a
  botnet spread across a range is banned as one block.
- **Reputation / Tor rules** *(optional)* — addresses on a downloaded threat list or
  the Tor exit-relay list are banned on their first packet, no threshold.

A banned source lands in an `ipset` and its packets are dropped (or rejected). A
once-a-minute collector records stats, resolves geo/owner/threat for what it sees, and
folds crowded ranges. The dashboard, whitelist and settings are all views over that
machinery.
