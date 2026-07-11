# Limitations and security notes

## Limitations

- **Slow scanners are not caught.** The traps are rate meters; a source that
  connects slower than the threshold (say once a minute) never exceeds it. Those
  scans are harmless background noise — detecting them would need per-packet logging
  the firmware doesn't have. The exception is abuse spread across many addresses of
  *one range*: the subnet trap catches it when the aggregate rate is high enough, and
  `COMPACT` folds a block that slowly fills with single bans.
- **TCP only.** The traps match TCP `SYN`. UDP scans/floods aren't metered by Tacet —
  though, as the [validation](validation.md) DoS tests show, a UDP flood to the
  router is dropped cheaply by the base firewall and creates no measurable load.
- **A ban does not break active sessions to the router.** The `INPUT` drop exempts
  `ESTABLISHED`/`RELATED` so your own tunnels are preserved; only *new* connections
  from the banned source are cut. Forwarded flows *are* cut immediately.
- **No packet logging.** The firmware lacks `xt_LOG`, so the event log records
  membership *changes* (ban / release / fold), not individual packets. The dashboard
  charts derive drop volume from the cumulative counter instead.
- **Enforcement is IP-based.** A determined attacker rotating through many addresses
  can keep probing; you can answer by banning their whole subnet in one entry, but
  this is not a substitute for authentication and patching on the services you
  expose.
- **The country/owner flag can lag a few minutes.** The big geo/owner databases
  resolve on a 5-minute cadence (`GEO_EVERY`, default 5); the *ban* is immediate, only
  the cosmetic flag/owner label appears slightly later.

## Security notes

- **The UI has no authentication.** It binds to the LAN IP only, on port 5050, and is
  meant for a trusted home LAN, like the router's own admin page. **Do not forward its
  port to the internet.** The API accepts LAN requests without a CSRF token, so a
  malicious website open on the LAN could in principle drive it (e.g. an `<img>` firing
  a GET). This is inherent to the no-authentication LAN-appliance model, not a defect;
  the mitigation is a trusted LAN and not exposing the port. All actions are reversible
  from the UI or the shell.
- **All input that becomes a ban or whitelist entry is validated** as an IP or CIDR
  (octets 0–255, mask 8–32 — a `/0`–`/7` block is never accepted) before it touches
  `ipset`. The API endpoint names and
  parameters are constrained to a known set; injection via the address field is
  rejected.
- **Free-text whitelist notes are sanitized** — quotes, backslashes, structural and
  control characters are stripped — so a note (whether set in the UI, imported from a
  backup, or hand-edited into the file) can never break a JSON payload or the import
  parser.
- **No data leaves the router.** All threat/geo/owner data is downloaded and resolved
  locally; the UI never contacts anything but the router's own CGI. The only outbound
  connections Tacet makes are the database downloads (to jsDelivr / the feed sources)
  and the GitHub release check for updates.
