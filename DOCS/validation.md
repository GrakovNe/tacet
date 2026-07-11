# Validation — testing, audit, effectiveness, resources

Everything here was measured on production hardware — a Keenetic ARMv8 (ARM64)
quad-core router with 1 GB RAM — driving real traffic from a separate cloud VM
against the router's public WAN. Both ends belong to the operator; the attacking
host runs on a provider that permits security testing. **All addresses are
redacted** with RFC 5737 documentation ranges (router WAN `198.51.100.10`, attacker
`203.0.113.45`); figures are aggregate only.

## 1. Regression suite

`tacet-test.sh` is a self-contained end-to-end suite (58 checks) that runs against a
live router. It is safe on a production router: every mutation uses documentation
ranges, the config is snapshotted and restored, and all test entries are cleaned up.

It covers: read endpoints return valid JSON; address validation (octets 0–255, mask
≤ 32); CIDR ban routing (a closed/open-surface CIDR lands in the subnet set) and its
lifecycle; whitelist notes and their sanitization; import robustness
(hostile input, control bytes, GET-vs-POST, empty body, override-of-empty-section);
backup round-trip; config validation and clamping; concurrency; the info-badge
regression; and — over SSH — netfilter rule integrity, hashlimit name lengths,
database sort correctness, collector clean-exit, the persistence save guard, and
engine/CGI count agreement. Result: **58/58 green**, idempotent across repeated runs.
Destructive tests (the whitelist-wipe round-trip, the config save) are gated on their
snapshots verifiably parsing, so a transient export failure skips them instead of
risking live data.

## 2. Security audit — the protection surface

Three rounds of live-attacker testing exercised every mechanism. Consolidated
results:

| Mechanism | Test | Result |
|---|---|---|
| **Closed-port auto-ban** | scan closed ports past the 8/min threshold | ✅ banned in seconds, into `tacet-scan` |
| **Threshold accuracy** | 6 SYN (under 8), then +15 (over) | ✅ 6 → no ban, +15 → banned; the rate meter is exact |
| **Forwarded-port auto-ban** | flood a forwarded port past the configured 45/min | ✅ banned into `tacet-flood` |
| **Subnet trap (isolated)** | per-IP trap off, flood one IP, subnet meter at 10/min | ✅ the whole `/24` banned into `tacet-cnet` — the subnet meter fires independently |
| **Reputation / first-packet ban** | add the source to `tacet-threat`, send one SYN | ✅ banned on the first packet, no threshold |
| **Drop effectiveness** | connect to an *open* forwarded port while banned | ✅ was reachable → times out when banned → reachable again after unban |
| **Sticky ban** | keep connecting while banned | ✅ the timeout never counts down — it refreshes on every dropped packet |
| **Reject policy** | `BAN_REJECT=yes`, connect while banned | ✅ `ConnectionRefused` in **0.02 s** (TCP reset) vs a multi-second silent-drop timeout |
| **Whitelist wins** | whitelist the attacker, then flood | ✅ never banned, still reachable — the whitelist is checked before the ban rules |
| **Master switch** | toggle off then on | ✅ off → all drop rules gone, source reachable; on → rules back, source re-blocked, ban survived the toggle |
| **Persistence (reboot sim)** | save / flush / restore the set | ✅ the ban survives — bans persist across reboots |

### DoS resilience

- **conntrack exhaustion** — a TCP SYN flood is banned within ~3 s; its dropped
  packets then add nothing and conntrack stayed bounded (~800 of the 32768-entry
  table). The fast ban plus the source's own port/concurrency limits cap its footprint.
- **Source spoofing** — a raw SYN flood with a forged source (47k pps) never reached
  the router: cloud egress anti-spoofing drops it, as it would a real attacker.
- **UDP flood** — Tacet is TCP-SYN-only, but a UDP flood to the router created **zero**
  conntrack entries and **zero** measurable load (dropped cheaply by the base
  firewall).

## 3. Load & stress testing

The router's only significant load source is its own web UI, not attack traffic.

| Load source | Router 1-min load |
|---|---|
| 40 concurrent API requests (legitimate) | **~7.3** |
| ~414 packet/s attack flood (banned source) | **~0.35** (idle) |

**API throughput vs concurrency** — the shell CGI plateaus at **~14 req/s**; past
~20 concurrent requests latency and load climb (requests queue), but none fail. In
real use the UI polls once per open tab per `REFRESH_SEC` — ten open dashboards at the
default 60 s is ~0.17 req/s, two orders of magnitude under the ceiling.

**Router usability during a sustained flood** — a 40-second, 80-thread connection
flood (16 282 attempts, ~414 pkt/s dropped): the source was banned within 5 s, the
**UI stayed responsive (~130–150 ms)**, and **load never rose above idle (~0.35)**.
Once banned, the source adds no measurable load, because dropping is an O(1) ipset
lookup plus `DROP`.

**Combined stress** — attack flood + a forced collector run + ten concurrent API
pollers, all at once: **30/30** requests returned valid JSON, peak load 1.43,
conntrack within bounds at ~868/32768. No requests failed or returned corrupt
responses.

## 4. Production effectiveness (~20 h of live operation)

A snapshot of the ban list after ~20 h on a real WAN connection — data on the
attackers Tacet catches in production, not a test:

- **~713 active bans** (666 single addresses + 47 whole-subnet), in steady state
  (new attackers arrive roughly as fast as old bans expire).
- **~314,000 packets dropped** from banned sources, **~970/min** (over the 5.4 h since
  the last rules rebuild reset the counter).
- **63 % of attackers originate in cloud/hosting** address space — top owners
  Microsoft/Azure, Akamai, Alibaba, UCLOUD, DigitalOcean, Amazon, Google. Rented VMs
  and scanners dominate. Top countries track hosting geography (US ~50 %, NL, DE, GB,
  SG, FR, CN, JP, RU).
- **86 %** of banned single IPs are also on the public threat feeds — the behaviour
  traps agree with reputation data.
- the remaining **~14 % were caught by behaviour alone** — actively scanning this
  router but on *no* public feed yet. These are what a reputation-only blocklist would
  miss.
- By observed activity: hundreds of port-scanners, dozens of brute-forcers, plus web,
  mail and VoIP abuse. Reputation/first-packet bans and subnet folds both fire in the
  event log.

## 5. Resource footprint

Tacet's resident footprint is negligible against the router's ~556 MB free.

**Memory**

| Component | Footprint |
|---|---|
| All ipsets (kernel) | **~0.6 MB** (threat 0.49 MB / 16.7k IPs dominates) |
| UI web server (`lighttpd`) RSS | ~4.6 MB |
| Databases on flash (geo+asn+threat+activity+tor `.dat`) | ~30 MB |
| Collector — peak RSS during a geo tick | **~3.6 MB** |
| CGI request — peak RSS (then exits) | ~5 MB |

The collector peaks at ~3.6 MB because the merge-join resolver *streams* the
355k+398k-row databases with a pointer instead of loading them into arrays (which
would be tens of MB).

**CPU**

| Operation | CPU (user) |
|---|---|
| Collector — geo tick (once every 5 min) | ~4.4 s |
| Collector — typical minute | ~0.4 s |
| CGI request | ~0.1–0.5 s |

Averaged, the collector is well under 2 % of one core on the quad-core ARM. Dropping
banned traffic is free (an ipset lookup + `DROP`), so no flood a single source can
generate moves the load off idle.

---

*Reproduce the suite with `./tacet-test.sh [router-ip]` (`SSHPASS=… ` for
non-interactive SSH). The audit and load scenarios were driven from a separate host;
this document records their outcomes.*
