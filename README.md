# Tacet

**A self-hosted auto-ban firewall for Keenetic routers (Entware).** It watches the
WAN, bans hosts that scan closed ports or flood forwarded services, and gives you a
small local dashboard to see and manage it — with a country flag, network owner (ASN)
and threat/abuse attribution for every address. Runs entirely on the router: no
cloud, no accounts, no telemetry. Enforcement is stock `ipset` + `iptables`.

*Tacet* is Latin for "it is silent": a banned source gets no reply.

## What it does

- **Closed-port trap** — a source probing ports you don't run is banned after a few
  `SYN`s per minute. This catches the constant background scanning every public IP
  receives.
- **Forwarded-service trap** — a source flooding a port you *do* forward (a web
  server, a game server) is banned past a higher, traffic-friendly threshold.
- **Subnet trap** — abuse spread across many addresses of one range drains a shared
  meter, and the whole block is banned as a single entry.
- **Threat & Tor reputation** *(optional)* — sources on locally-downloaded threat
  feeds or the Tor exit list are dropped on their first packet.
- **Ban-list compaction** — a block that slowly fills with single bans is folded
  into one subnet ban.

Bans are **sticky idle-timeouts**: they last 24 h from the source's *last* attempt,
so a persistent attacker stays banned for as long as it keeps trying. Bans survive
reboots. The dashboard shows live charts, the ban list with per-address intelligence
(country, owner, abuse categories), ban candidates, a whitelist with notes, an event
log, and one-file backup/restore.

## Install

On the router (Keenetic + Entware), as root:

```sh
opkg install ipset iptables lighttpd lighttpd-mod-cgi
curl -fsSL https://raw.githubusercontent.com/GrakovNe/tacet/main/install.sh -o /tmp/tacet-install.sh
sh /tmp/tacet-install.sh
```

The installer fetches the rest of the release itself and asks a few questions
(headless sessions install with the defaults). Then open
`http://<router-LAN-IP>:5050`. Updates are one click from the UI.

## Documentation

Full docs are in **[`DOCS/`](DOCS/)** — English, with a Russian mirror in
[`DOCS/ru/`](DOCS/ru/):

- **[How it works](DOCS/how-it-works.md)** — the traps, bans, engine rules, collector, databases and dropping policy.
- **[Install & update](DOCS/install-and-update.md)** — requirements, install (including the codeload fallback), in-place updates, uninstall.
- **[Configuration](DOCS/configuration.md)** — every setting, the config file, the CLI, files and locations.
- **[Validation](DOCS/validation.md)** — security audit, load testing, production effectiveness and resource footprint, measured on the router.
- **[Limitations & security](DOCS/limitations.md)** — what it deliberately doesn't do.

A live regression suite (`tacet-test.sh`, 58 checks) runs against a real router.

## License

MIT © Max Grakov 2026. Tacet is an independent, unofficial project, not affiliated
with Keenetic.
