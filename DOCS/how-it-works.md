# How Tacet works

Tacet has three moving parts:

1. **The engine** — `50-tacet.sh`, a Keenetic `netfilter.d` hook that (re)builds all
   the `iptables` rules and `ipset` sets. It runs on boot, on every firewall rebuild,
   and whenever a setting changes.
2. **The collector** — `tacet-collect.sh`, run once a minute by cron. It records
   stats, resolves geo/owner/threat for visible addresses, folds crowded subnets, and
   writes the event log.
3. **The UI** — a static `index.html` + `tacet.js` served by a dedicated `lighttpd`,
   talking to `api.cgi` (a shell CGI) for JSON. It renders; it never enforces.

Enforcement is entirely `ipset` + `iptables`. The UI can be stopped and Tacet still
protects.

## The ban sets

Every ban is membership in one of **four** ban `ipset`s. Two more are *reference* sets
(the threat and Tor lists) — checked by the first-packet rules but never holding bans.
All six:

| Set | Type | Holds |
|---|---|---|
| `tacet-scan` | `hash:ip` | single IPs caught on closed ports (a hand-typed CIDR ban is routed to `tacet-cnet`) |
| `tacet-flood` | `hash:ip` | single IPs caught on forwarded ports (a hand-typed CIDR ban is routed to `tacet-fnet`) |
| `tacet-cnet` | `hash:ip` + netmask | whole `/SUBNET_MASK` blocks, closed-port abuse |
| `tacet-fnet` | `hash:ip` + netmask | whole `/SUBNET_MASK` blocks, forwarded-port abuse |
| `tacet-threat` | `hash:ip` | the downloaded threat list (a *reference* set, not bans) |
| `tacet-tor` | `hash:ip` | the downloaded Tor exit-relay list (reference set) |

Plus `tacet-allow` (`hash:net`) — the whitelist, checked before everything.

## The traps (how a source gets banned)

All traps use `xt_hashlimit`, the kernel's per-source rate meter. Each is a single
`iptables` rule whose `-j SET --add-set` adds the offending source to a ban set once
it exceeds the rate. The threshold is baked into the meter's name, so changing it
starts a fresh count.

### Closed-port trap (`TRAP_CLOSED`, on `INPUT`)

A `SYN` to a port on the router that nothing listens on is unsolicited by
definition. A source sending more than **`BURST`** (default 8) `SYN`/min to such
ports is added to `tacet-scan`. This is the trap that fires most often, since
background scanning constantly probes closed ports.

### Forwarded-port trap (`TRAP_OPEN`, on `FORWARD`)

For each port in **`SVC_PORTS`** (ports you forward to an internal server), a source
sending more than **`SVC_BURST`** (default 60) `SYN`/min is added to `tacet-flood`.
The threshold is higher because legitimate traffic arrives here — 60/min stops a
flood without affecting a real browser.

### Subnet trap (`TRAP_SUBNET`, optional, off by default)

The same two meters, but keyed by the `/SUBNET_MASK` network (default `/24`) instead
of the single address. Abuse spread thinly across a whole range — each address below
the per-IP threshold — drains one shared bucket; when the combined rate exceeds
**`SUBNET_BURST`** (default 30/min) the entire block is banned in one entry
(`tacet-cnet` for closed ports, `tacet-fnet` for forwarded). Off by default because
banning whole blocks is deliberate collateral — turn it on when a botnet rotates
addresses inside one range.

### Reputation and Tor rules (`THREAT_BAN` / `TOR_BAN`, optional, off by default)

These don't meter rate — they ban on the **first packet**. A rule matches any source
in the `tacet-threat` (or `tacet-tor`) reference set and adds it straight to a ban
set. Its first `SYN` is dropped and it's banned for the full duration, no threshold.
Toggling the feature off frees the reference set. The threat set comes from the
downloaded databases (see below).

## The drop (what a ban does)

For each of the four ban sets, `INPUT` and `FORWARD` carry two rules:

1. A **refresh** rule (`-j SET --add-set … --exist`) that re-stamps the ban's timeout
   on every packet from a banned source.
2. A **drop** rule that discards the packet.

The order matters. Because the refresh runs first, **the ban is a sticky idle
timeout**: it lasts `BAN_TTL` (default 24 h) from the *last* attempt, not the first.
A persistent source stays blocked; the ban lapses only 24 h after its last attempt.

The `INPUT` drop exempts `ESTABLISHED`/`RELATED`, so a ban does not break a live
session *to the router itself* (your own tunnels survive); only new connections are
cut. Forwarded flows are cut immediately.

### Dropping policy (`BAN_REJECT`)

- **Drop** (default) — the packet is silently discarded, so the source gets no
  response and retransmits until its own TCP stack times out.
- **Reject** — the router answers a banned TCP source with a `tcp-reset` (and
  everything else with ICMP port-unreachable). This ends the retransmit storm sooner
  but confirms a host exists at this address. Drop is the safer default.

## The master switch (`MASTER`)

`MASTER=no` makes the engine remove **all** Tacet rules — protection fully off — while
leaving the ban sets intact. Turning it back on rebuilds every rule; existing bans
are still in the sets, so they take effect again immediately.

## Sticky bans and persistence

Bans survive a reboot. A cron job saves the four ban sets to `/opt/etc/*.save` every
30 minutes (to a temp file, swapped in only when `ipset save` actually produced the set
— its `create` line is present — so an early-boot save before the sets exist can't wipe
a good snapshot, while a deliberately-cleared set still persists). On boot the engine
restores them if the live set is empty. A deliberate flush (unban-all, override
restore) refreshes the snapshot immediately, so the next rebuild or reboot cannot
resurrect what was just cleared; a snapshot taken under a different `SUBNET_MASK` is
discarded rather than re-masked into the wrong blocks.

## The collector (once a minute)

`tacet-collect.sh` does the non-enforcement work:

- **Stats** — appends `epoch,closed,open,dropped,cnet,fnet` to a CSV (kept ~25 h) for
  the dashboard charts. The dropped count is the exact `iptables -x` cumulative counter
  (the charts derive the per-minute delta from it).
- **Resolution** — for every address currently visible (banned, whitelisted, or in
  the connection table) it looks up country, network owner, threat score and abuse
  category from the local databases and caches the result. The cheap threat/activity
  lookup runs every minute (it drives the red badge); the two big databases —
  geo (355k ranges) and owner/ASN (398k ranges) — resolve on a **`GEO_EVERY`-minute**
  cadence (default 5) since a country flag appearing a few minutes late costs
  nothing, while the ban itself is immediate. The resolver is a merge-join that
  streams each database once, holding only a few MB of RAM.
- **Compaction** (`COMPACT`, optional) — every `COMPACT_EVERY` minutes it sweeps the
  ban list and folds any `/SUBNET_MASK` block that has quietly accumulated many
  single-IP bans (once **`COMPACT_PCT`** % of the block is banned) into one
  whole-subnet ban. This catches slow abuse the rate trap misses: a botnet whose
  addresses each connect rarely never exceeds the per-minute threshold, but
  accumulates dozens of single bans in one block over hours. Folding shrinks the list
  and blocks the rest of the range in advance.
- **Event log** (`LOG_ENABLED`) — records ban/release/fold/config events by diffing
  the sets against a snapshot. A mass-ban burst (thousands of new bans in a minute)
  logs a single summary line instead of one entry each.

## The databases

Five local databases (four update jobs maintain them — the threat job builds both the
threat and activity lists), refreshed on demand or by a daily auto-update
(`AUTO_DB_UPDATE`). All free, no keys, downloaded to the router:

| Database | Source | File | Drives |
|---|---|---|---|
| **Geo** (IP→country) | dbip-country via jsDelivr | `tacet-geo.dat` (~8 MB) | the country flags |
| **Owner / ASN** | dbip-asn via jsDelivr | `tacet-asn.dat` (~20 MB) | the network-owner line |
| **Threat** | IPsum (30+ abuse feeds), ≥3-list confidence | `tacet-threat.dat` (~0.4 MB) | the red `!` badge + reputation auto-ban |
| **Activity** | blocklist.de per-service, CINS, GreenSnow, Feodo Tracker | `tacet-activity.dat` (~0.9 MB) | *what* an address was seen doing (port-scan, brute-force, mail, web, VoIP, botnet C2) |
| **Tor exit list** | torproject.org bulk exit list (FireHOL mirror fallback) | `tacet-tor.dat` (~30 KB) | the Tor auto-ban rule |

The databases store integer IP ranges sorted for a binary-search / merge-join
resolver. Geo and ASN arrive pre-sorted from source; the threat/Tor/activity lists
are sorted on the router with a fixed-width key (busybox `sort -n` overflows above
2³¹, so the sort uses a zero-padded lexical key instead).
