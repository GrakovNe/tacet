#!/bin/sh
# Tacet DEV deploy (run from the repository directory on your machine).
# End users install with install.sh ON the router instead — see README.
#
#   ./dev-deploy.sh              # to root@192.168.1.1
#   ./dev-deploy.sh root@10.0.0.1
#
# The password is asked once (ControlMaster). Non-interactive:
#   SSHPASS=password ./dev-deploy.sh   (requires sshpass)
#
# Router prerequisites: Entware with opkg packages ipset, iptables,
# lighttpd + lighttpd-mod-cgi. The WAN interface in 50-tacet.sh is ppp0.
# (c) Max Grakov 2026, MIT License.

set -e

HOST="${1:-root@192.168.1.1}"
DIR="$(cd "$(dirname "$0")" && pwd)"
CTL="/tmp/tacet-install-$$"
OPTS="-o HostKeyAlgorithms=+ssh-rsa -o StrictHostKeyChecking=accept-new -o ControlPath=$CTL"

if [ -n "$SSHPASS" ] && command -v sshpass >/dev/null 2>&1; then
    SSH="sshpass -e ssh $OPTS"
    SCP="sshpass -e scp -O $OPTS"
else
    SSH="ssh $OPTS"
    SCP="scp -O $OPTS"
fi

run() { $SSH "$HOST" "$@"; }

for f in 50-tacet.sh tacet-collect.sh tacet-geo-update.sh tacet-threat-update.sh tacet-asn-update.sh tacet-tor-update.sh tacet-update.sh tacet-countries VERSION index.html api.cgi assets/tacet.css assets/tacet.js \
         lighttpd-tacet.conf S85tacet-ui S10crond crontab-root; do
    [ -f "$DIR/$f" ] || { echo "error: file $f is missing next to the installer"; exit 1; }
done

echo "== connecting to $HOST (password asked once)"
$SSH -M -o ControlPersist=180 "$HOST" true

echo "== checking the router environment"
run '
  err=0
  [ -x /opt/sbin/ipset ]    || { echo "  no ipset:    opkg install ipset"; err=1; }
  [ -x /opt/sbin/iptables ] || { echo "  no iptables: opkg install iptables"; err=1; }
  [ -x /opt/sbin/lighttpd ] || { echo "  no lighttpd: opkg install lighttpd lighttpd-mod-cgi"; err=1; }
  [ -f /opt/lib/lighttpd/mod_cgi.so ] || { echo "  no mod_cgi:  opkg install lighttpd-mod-cgi"; err=1; }
  [ -d /opt/etc/ndm/netfilter.d ] || { echo "  no /opt/etc/ndm/netfilter.d (is this Keenetic with Entware?)"; err=1; }
  [ $err -eq 0 ] || exit 1
  mkdir -p /opt/share/tacet /opt/var/spool/cron/crontabs /opt/var/run /opt/var/log
'

LANIP=$(run "ip -4 addr show br0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1")
[ -n "$LANIP" ] || { echo "error: could not detect LAN IP (br0)"; exit 1; }
echo "== router LAN IP: $LANIP"

echo "== copying files"
# scp to a destination-adjacent .new, then mv on the router (same fs = atomic
# rename): an in-place scp TRUNCATES the target first, so a browser poll could
# execute a half-copied api.cgi and a mid-copy engine/collector run would read a
# torn script — install.sh's inst() maintains the same invariant.
$SCP "$DIR/50-tacet.sh"         "$HOST:/opt/etc/ndm/netfilter.d/50-tacet.sh.new"
$SCP "$DIR/tacet-collect.sh"    "$HOST:/opt/etc/tacet-collect.sh.new"
$SCP "$DIR/tacet-geo-update.sh"      "$HOST:/opt/etc/tacet-geo-update.sh.new"
$SCP "$DIR/tacet-threat-update.sh"   "$HOST:/opt/etc/tacet-threat-update.sh.new"
$SCP "$DIR/tacet-asn-update.sh"      "$HOST:/opt/etc/tacet-asn-update.sh.new"
$SCP "$DIR/tacet-tor-update.sh"      "$HOST:/opt/etc/tacet-tor-update.sh.new"
$SCP "$DIR/tacet-update.sh"          "$HOST:/opt/etc/tacet-update.sh.new"
$SCP "$DIR/tacet-countries"          "$HOST:/opt/etc/tacet-countries.new"
$SCP "$DIR/index.html"            "$HOST:/opt/share/tacet/index.html.new"
$SCP "$DIR/api.cgi"               "$HOST:/opt/share/tacet/api.cgi.new"
$SCP "$DIR/assets/tacet.css"         "$HOST:/opt/share/tacet/tacet.css.new"
$SCP "$DIR/assets/tacet.js"          "$HOST:/opt/share/tacet/tacet.js.new"
$SCP "$DIR/lighttpd-tacet.conf" "$HOST:/opt/etc/lighttpd-tacet.conf.new"
$SCP "$DIR/S85tacet-ui"         "$HOST:/opt/etc/init.d/S85tacet-ui.new"
# S10crond is shared Entware infrastructure — never overwrite an existing one
$SCP "$DIR/S10crond"              "$HOST:/tmp/tacet-S10crond"
$SCP "$DIR/crontab-root"          "$HOST:/tmp/tacet-crontab"
# version marker LAST (same invariant as install.sh): if any earlier copy fails,
# the router must not already claim the new version
$SCP "$DIR/VERSION"               "$HOST:/opt/etc/tacet-version.new"

run "
  # chmod the STAGED copies first, then mv preserves the mode — so a file is never
  # in place but non-executable (a netfilter event / cron tick / CGI poll in that
  # window would silently skip the hook, fail the collector, or 500 the UI). scp -O
  # copies the source mode, and several sources are 0644 in git.
  for f in /opt/etc/ndm/netfilter.d/50-tacet.sh.new /opt/etc/tacet-collect.sh.new \
           /opt/etc/tacet-update.sh.new /opt/share/tacet/api.cgi.new \
           /opt/etc/tacet-geo-update.sh.new /opt/etc/tacet-threat-update.sh.new \
           /opt/etc/tacet-asn-update.sh.new /opt/etc/tacet-tor-update.sh.new \
           /opt/etc/init.d/S85tacet-ui.new; do [ -f \"\$f\" ] && chmod +x \"\$f\"; done
  # atomically swap every staged file into place; VERSION marker last
  for f in /opt/etc/ndm/netfilter.d/50-tacet.sh /opt/etc/tacet-collect.sh \
           /opt/etc/tacet-geo-update.sh /opt/etc/tacet-threat-update.sh \
           /opt/etc/tacet-asn-update.sh /opt/etc/tacet-tor-update.sh \
           /opt/etc/tacet-update.sh /opt/etc/tacet-countries \
           /opt/share/tacet/index.html /opt/share/tacet/api.cgi \
           /opt/share/tacet/tacet.css /opt/share/tacet/tacet.js \
           /opt/etc/lighttpd-tacet.conf /opt/etc/init.d/S85tacet-ui \
           /opt/etc/tacet-version; do
      [ -f \"\$f.new\" ] && mv \"\$f.new\" \"\$f\"
  done
  # shared init script: install only when absent (a user's custom crond setup
  # must survive our deploys)
  [ -f /opt/etc/init.d/S10crond ] || { chmod +x /tmp/tacet-S10crond; mv /tmp/tacet-S10crond /opt/etc/init.d/S10crond; }
  rm -f /tmp/tacet-S10crond
  chmod +x /opt/etc/init.d/S10crond 2>/dev/null
  # write the actual LAN IP into the UI bind
  sed -i \"s|^server.bind.*|server.bind          = \\\"$LANIP\\\"|\" /opt/etc/lighttpd-tacet.conf
  # crontab: append our lines without touching others
  CT=/opt/var/spool/cron/crontabs/root
  touch \$CT && chmod 600 \$CT
  if ! grep -qF tacet-collect.sh \$CT; then grep -vE '^#|^[[:space:]]*\$' /tmp/tacet-crontab >> \$CT
  else
    # scope the re-sync to OUR line: a bare 'ipset save' match would delete the
    # user's own unrelated persistence jobs
    grep -vE 'ipset save.*tacet|tacet.*ipset save' \$CT > \$CT.n && mv \$CT.n \$CT
    grep -E '^[^#].*ipset save' /tmp/tacet-crontab >> \$CT
  fi
  rm -f /tmp/tacet-crontab
"

echo "== applying firewall rules"
run 'table=filter type=iptables sh /opt/etc/ndm/netfilter.d/50-tacet.sh'

echo "== starting services"
run '
  /opt/etc/init.d/S10crond restart >/dev/null 2>&1 || /opt/etc/init.d/S10crond start >/dev/null 2>&1
  /opt/etc/init.d/S85tacet-ui restart >/dev/null 2>&1
  sleep 1
'

echo "== seeding the geo database in the background (for the country flags)"
run 'chmod +x /opt/etc/tacet-geo-update.sh /opt/etc/tacet-threat-update.sh /opt/etc/tacet-asn-update.sh /opt/etc/tacet-tor-update.sh
     [ -f /opt/etc/tacet-geo.dat ]    || sh /opt/etc/tacet-geo-update.sh    >/dev/null 2>&1 &
     [ -f /opt/etc/tacet-threat.dat ] || sh /opt/etc/tacet-threat-update.sh >/dev/null 2>&1 &
     [ -f /opt/etc/tacet-asn.dat ]    || sh /opt/etc/tacet-asn-update.sh    >/dev/null 2>&1 &'

echo "== verifying"
run "
  ok=0
  iptables -S INPUT | grep -q 'match-set tacet-scan src' && echo '  + drop rule present' || ok=1
  iptables -S INPUT | grep -q 'add-set tacet-scan src'   && echo '  + trap present (or disabled in settings)'
  netstat -tln | grep -q ':5050 ' && echo '  + UI listening on :5050' || ok=1
  pidof crond >/dev/null && echo '  + crond running' || ok=1
  exit \$ok
"

$SSH -O exit "$HOST" 2>/dev/null || true
echo
echo "Done: http://$LANIP:5050"
