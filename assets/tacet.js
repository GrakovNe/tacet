/* Tacet UI. All data comes from /api.cgi as JSON; this file renders it,
   handles actions, the theme, the settings menu, the chart and auto-refresh.
   Served statically from /opt/share/tacet/tacet.js (loaded with defer).
   (c) Max Grakov 2026, MIT License. */
(function () {
  "use strict";

  /* ---------- theme (applied ASAP to avoid a flash) ---------- */
  var TKEY = "tacet-theme";
  // localStorage throws (not just returns null) when site data is blocked — a bare
  // access in the boot path would abort the whole IIFE and leave a blank page.
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function themeNow() { return lsGet(TKEY) || "auto"; }
  function applyTheme(v) {
    var r = document.documentElement;
    if (v === "auto") r.removeAttribute("data-theme"); else r.setAttribute("data-theme", v);
  }
  applyTheme(themeNow());

  /* ---------- tiny helpers ---------- */
  function $(id) { return document.getElementById(id); }
  // iterate a NodeList without NodeList.prototype.forEach — that method is newer
  // (Chrome 51+/Edge 16+) than the fetch baseline this file otherwise targets,
  // and using it in the boot path blanked the whole page on older browsers
  function each(list, fn) { for (var i = 0; i < list.length; i++) fn(list[i], i); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  // private / loopback / link-local — addresses that never have a country,
  // so "Unknown" would be misleading (accepts a bare IP or a CIDR)
  function isLocal(ip) {
    var v = ip2int(String(ip).split("/")[0]);
    if (isNaN(v)) return false;
    var o1 = v >>> 24;
    return o1 === 10 || o1 === 127 ||
      (v >>> 20) === 0xAC1 ||    // 172.16.0.0/12
      (v >>> 16) === 0xC0A8 ||   // 192.168.0.0/16
      (v >>> 16) === 0xA9FE;     // 169.254.0.0/16
  }
  function flag(cc, country, ip) {
    if (ip && isLocal(ip)) return '<span class="flag home" title="Local network">' + SVG +
      '<path d="m3 9.5 9-7 9 7V20a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 20Z"/><path d="M9.5 21.5v-8h5v8"/></svg></span> ';
    if (cc && cc.length === 2 && cc !== "?") {
      var em = String.fromCodePoint(127397 + cc.charCodeAt(0), 127397 + cc.charCodeAt(1));
      return '<span class="flag" title="' + esc(country || cc) + '">' + em + "</span> ";
    }
    return '<span class="flag unk" title="Unknown">🏳</span> ';
  }
  // info badge right of every IP: hover/click opens a detail popup (owner /
  // country / reputation, see initInfoPop). Neutral "i" normally; a red "!" when
  // the address is on the threat list or a categorised abuse feed.
  // o = any row item carrying ip / threat / act / org / country.
  function infoBadge(o) {
    if (isLocal(o.ip)) return "";   // a LAN address has no owner / country / reputation to speak of
    var bad = o.threat > 0 || o.act > 0;
    return ' <span class="ibadge' + (bad ? " bad" : "") + '" data-ip="' + esc(o.ip) +
      '" data-threat="' + (o.threat || 0) + '" data-acts="' + (o.act || 0) +
      '" data-org="' + esc(o.org || "") +
      '" data-country="' + esc(o.country || "") +
      '" aria-label="Address details">' + SVG +
      (bad ? '<circle cx="12" cy="12" r="9.5"/><line x1="12" y1="7.5" x2="12" y2="12.5"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
           : '<circle cx="12" cy="12" r="9.5"/><line x1="12" y1="11" x2="12" y2="16.5"/><line x1="12" y1="7.5" x2="12.01" y2="7.5"/>') +
      "</svg></span>";
  }
  // whitelist ranges for the popup's "Whitelist" note — refreshed from every
  // payload that carries "wl" (the list is small, so it ships whole)
  var WL = [];
  function ip2int(ip) {
    // return NaN on anything malformed so the isNaN() guards in isLocal/wlHit/
    // setWl/foldPreview actually fire — a bare `>>> 0` turns NaN into 0, which
    // would silently fold "10.0.0." or "256.0.0.1" into a real address
    var p = String(ip).split("."), n = 0, i;
    if (p.length !== 4) return NaN;
    for (i = 0; i < 4; i++) {
      if (!/^[0-9]{1,3}$/.test(p[i]) || +p[i] > 255) return NaN;
      n = n * 256 + (+p[i]);
    }
    return n >>> 0;
  }
  function setWl(list) {
    WL = [];
    (list || []).forEach(function (e) {
      var m = e.split("/"), v = ip2int(m[0]);
      if (isNaN(v)) return;
      var size = Math.pow(2, 32 - (m[1] ? +m[1] : 32)), base = v - (v % size);
      WL.push([base, base + size - 1, e]);
    });
  }
  function wlHit(ip) {   // the whitelist entry covering ip (or its base, for a CIDR row)
    var v = ip2int(String(ip).split("/")[0]);
    if (isNaN(v)) return null;
    for (var i = 0; i < WL.length; i++) if (v >= WL[i][0] && v <= WL[i][1]) return WL[i][2];
    return null;
  }
  var FSEQ = 0;   // request sequence: a slow stale response must not overwrite a newer render
  function getJSON(fn, cb) {
    var seq = ++FSEQ;
    fetch("/api.cgi?fn=" + fn, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (seq !== FSEQ) return;   // a newer request has been issued since
        if (d && d.wl) setWl(d.wl);
        cb(d);
        // stamp the freshness footer only on SUCCESS — stamping at request time
        // kept advancing the clock while the backend was down
        var f = $("updFoot");
        if (f) f.textContent = "Updated " + new Date().toTimeString().slice(0, 8);
      })
      .catch(function (e) { console.warn("tacet: fetch " + fn + " failed", e); });
  }
  // run an action, then refresh the current tab (msg = optional confirm text)
  function act(params, msg, done) {
    if (msg && !confirm(msg)) return;
    fetch("/api.cgi?fn=" + params, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        // surface every rejection, not just the whitelisted case — a silent
        // {ok:false} let a bad address vanish looking like it was accepted
        if (j && j.ok === false) {
          if (j.err === "whitelisted") alert("Not banned: this address is in the whitelist.");
          else if (!done) alert("Rejected: " + (j.err || "invalid input") + ".");
        }
        if (done) done(j);
        loadTab(TAB);
      })
      .catch(function (e) {
        console.warn("tacet: action failed", e);
        if (done) done(null);   // let callers release their pending UI state
      });
  }

  /* ---------- icons (line style, currentColor) ---------- */
  var SVG = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">';
  var IC = {
    ban:   SVG + '<path d="m15 12-8.373 8.373a1 1 0 1 1-3-3L12 9"/><path d="m18 15 4-4"/><path d="m21.5 11.5-1.914-1.914A2 2 0 0 1 19 8.172V7l-2.26-2.26a6 6 0 0 0-4.202-1.756L9 2.96l.92.82A6.18 6.18 0 0 1 12 8.4V10l2 2h1.172a2 2 0 0 1 1.414.586L18.5 14.5"/></svg>',
    unban: SVG + '<rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>',
    white: SVG + '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>',
    trash: SVG + '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    pen:   SVG + '<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/></svg>'
  };
  function iact(extra, title, params, icon, msg) {
    return '<a class="iact' + (extra ? " " + extra : "") + '" title="' + esc(title) +
      '" href="#" data-act="' + esc(params) + '"' + (msg ? ' data-confirm="' + esc(msg) + '"' : "") +
      ">" + IC[icon] + "</a>";
  }
  // the "Move to whitelist" row-action; when the address is already covered
  // by a whitelist entry it degrades to a green non-clickable indicator
  // (WL is refreshed before every render)
  function wlAct(ip) {
    var hit = wlHit(ip);
    if (hit) return '<span class="iact inwl" title="Already whitelisted (' + esc(hit) + ')">' + IC.white + "</span>";
    return iact("", "Move to whitelist", "white&ip=" + encodeURIComponent(ip), "white");
  }

  /* ---------- tab router ---------- */
  var TABS = ["dash", "protection", "whitelist", "settings"];
  var TAB = "dash";
  var CFG_DIRTY = false;   // unsaved edits in the settings form (pauses auto-refresh repaint)
  var BANIPS = null;   // {scan:[],flood:[]} single-IP bans for the live fold preview
  function currentHashTab() {
    var h = location.hash.replace("#", "");
    if (TABS.indexOf(h) >= 0) return h;
    var m = /[?&]page=([a-z]+)/.exec(location.search);   // legacy /?page=... links
    if (m && TABS.indexOf(m[1]) >= 0) return m[1];
    return "dash";
  }
  function showTab(t) {
    TAB = t;
    CFG_DIRTY = false;   // entering a tab starts clean (any abandoned edit was never saved)
    TABS.forEach(function (x) {
      $("tab-" + x).hidden = x !== t;
      var a = document.querySelector('#nav a[data-tab="' + x + '"]');
      if (a) a.classList.toggle("on", x === t);
    });
    loadTab(t);
  }

  /* ---------- renderers ---------- */
  var REFRESH = 60;
  var BOOTVER = null;    // backend version this page was loaded against
  var UPD_POLL = null;   // single pending update-poll timer (no ratcheting)

  function renderDash(d) {
    REFRESH = d.refresh;
    $("verFoot").textContent = "v" + d.version;
    var mc = $("masterCard");
    mc.classList.toggle("off", !d.master);
    $("masterTitle").textContent = d.master ? "Enabled" : "Disabled";
    $("masterSub").textContent = d.master ? "Keeping the silence" : "Silence broken — nothing is filtering";
    $("masterSw").setAttribute("aria-checked", d.master ? "true" : "false");
    tile("tTotal", d.counts.total);
    tile("tClosed", d.counts.closed);
    tile("tOpen", d.counts.open);
    tile("tDropped", d.counts.dropped);
    renderChart(d.chart);
    renderDrops(d.drops);
    var h;
    if (d.conns.length) {
      h = "<table><tr><th>IP</th><th>connections</th><th></th></tr>";
      d.conns.forEach(function (c) {
        h += '<tr><td class="ip">' + flag(c.cc, c.country, c.ip) + esc(c.ip) + infoBadge(c) +
          '</td><td class="num">' + c.n + '</td><td class="r">' +
          wlAct(c.ip) +
          iact("danger", "Ban", "ban&cat=closed&ip=" + encodeURIComponent(c.ip), "ban") +
          "</td></tr>";
      });
      h += "</table>";
    } else h = '<div class="empty">No external connections right now.</div>';
    $("connsBox").innerHTML = h;
  }

  /* shared bar-chart scaffolding: gridlines + per-bucket hover slots. draw(b, j,
     geometry) returns the svg rects for one bucket; hovAttrs(b) its tooltip data. */
  var CH = { W: 884, H: 156, PAD: 6 };
  function barChart(buckets, mx, draw, hovAttrs) {
    var W = CH.W, H = CH.H, PAD = CH.PAD;
    var nb = buckets.length, plotH = H - 2 * PAD, slot = W / nb, barW = slot * 0.68, off = (slot - barW) / 2;
    var s = '<svg class="chart" viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none">';
    for (var g = 1; g <= 3; g++) {
      var yy = (PAD + plotH * g / 4).toFixed(1);
      s += '<line x1="0" y1="' + yy + '" x2="' + W + '" y2="' + yy + '" stroke="var(--grid)" stroke-width="1"/>';
    }
    buckets.forEach(function (b, j) {
      s += draw(b, j * slot + off, barW, plotH, mx);
      s += '<rect class="hov" x="' + (j * slot).toFixed(1) + '" y="0" width="' + slot.toFixed(1) + '" height="' + H + '" fill="transparent" data-t="' + b[0] + '"' + hovAttrs(b) + "/>";
    });
    return s + "</svg>";
  }
  // chart scale is a per-browser preference (like the theme): log keeps a
  // single burst from flattening the rest of the chart, linear shows true
  // proportions. log1p keeps v=0 at exactly zero height on either scale.
  var SKEY = "tacet-scale";
  function scaleNow() { return lsGet(SKEY) === "linear" ? "linear" : "log"; }
  function barH(v, mx, plotH) {
    if (v <= 0) return 0;
    return scaleNow() === "linear" ? v / mx * plotH : Math.log(1 + v) / Math.log(1 + mx) * plotH;
  }
  function yaxis(mx) {
    var mid = scaleNow() === "linear" ? Math.floor(mx / 2)
      : Math.round(Math.exp(Math.log(1 + mx) / 2) - 1);   // value at half height on the log scale
    return '<div class="yaxis"><span>' + fmtK(mx) + "</span><span>" + fmtK(mid) + "</span><span>0</span></div>";
  }
  function fmtK(v) { return v >= 10000 ? Math.round(v / 1000) + "k" : v >= 1000 ? (v / 1000).toFixed(1) + "k" : v; }
  // big-number tiles: 1500 -> "1.5K", 234800 -> "234.8K", 2_000_000 -> "2M"
  function fmtNum(v) {
    v = +v || 0;
    function t(x) { return x.toFixed(1).replace(/\.0$/, ""); }
    if (v >= 1e9) return t(v / 1e9) + "B";
    if (v >= 1e6) return t(v / 1e6) + "M";
    if (v >= 1000) return t(v / 1000) + "K";
    return String(v);
  }
  // set a stat tile's short value, with the exact number on hover
  function tile(id, v) {
    var el = $(id);
    el.textContent = fmtNum(v);
    el.title = (+v || 0).toLocaleString("en-US");
  }
  function niceMax(p) {  // smallest 1/2/5×10^k not below the peak
    if (p <= 5) return 5;
    for (var m = 10; ; m *= 10) {
      if (p <= m) return m;
      if (p <= m * 2) return m * 2;
      if (p <= m * 5) return m * 5;
    }
  }

  function renderChart(ch) {
    if (!ch.buckets.length) {
      $("chartBox").innerHTML = '<div class="empty">Collecting data — the chart appears in a couple of minutes.</div>';
      return;
    }
    var mx = Math.max(ch.max, 1), H = CH.H, PAD = CH.PAD;
    var s = barChart(ch.buckets, mx, function (b, x, barW, plotH) {
      // stack at the cumulative totals: on the log scale the segment boundary
      // sits at log(closed), so the full bar height reads as log(closed+open)
      var chh = barH(b[1], mx, plotH), oh = barH(b[1] + b[2], mx, plotH) - chh;
      var yc = H - PAD - chh, yo = yc - oh, r = "";
      if (chh > 0) r += '<rect x="' + x.toFixed(1) + '" y="' + yc.toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + chh.toFixed(1) + '" rx="2" fill="var(--closed)"/>';
      if (oh > 0)  r += '<rect x="' + x.toFixed(1) + '" y="' + yo.toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + oh.toFixed(1) + '" rx="2" fill="var(--open)"/>';
      return r;
    }, function (b) {
      return ' data-c="' + b[1] + '" data-o="' + b[2] + '"';
    });
    $("chartBox").innerHTML =
      '<div class="chartwrap">' + yaxis(mx) + s + "</div>" +
      '<div class="legend below"><span><span class="dot" style="background:var(--closed)"></span>closed-port</span>' +
      '<span><span class="dot" style="background:var(--open)"></span>open-port</span></div>';
  }

  function renderDrops(buckets) {
    if (!buckets || !buckets.length) {
      $("dropsBox").innerHTML = '<div class="empty">Collecting data — the chart appears in a couple of minutes.</div>';
      return;
    }
    var peak = 0;
    buckets.forEach(function (b) { if (b[1] > peak) peak = b[1]; });
    var mx = niceMax(peak), H = CH.H, PAD = CH.PAD;
    var s = barChart(buckets, mx, function (b, x, barW, plotH) {
      var h = barH(b[1], mx, plotH);
      return h > 0 ? '<rect x="' + x.toFixed(1) + '" y="' + (H - PAD - h).toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + h.toFixed(1) + '" rx="2" fill="var(--drop)"/>' : "";
    }, function (b) {
      return ' data-v="' + b[1] + '"';
    });
    $("dropsBox").innerHTML =
      '<div class="chartwrap">' + yaxis(mx) + s + "</div>" +
      '<div class="legend below"><span><span class="dot" style="background:var(--drop)"></span>packets dropped</span></div>';
  }

  // Each row carries its own cat (closed/open for single IPs, cnet/fnet for whole
  // subnets) so the action routes to the right set; b.ip is already display-ready
  // (a /N for subnet rows, which is enough to read them as a block).
  function banRows(items) {
    var h = '<table><tr><th>IP / subnet</th><th title="Idle timeout — the ban lapses this long after the source stops trying. Any new attempt resets it to the full ban duration.">idle-out</th><th></th></tr>';
    items.forEach(function (b) {
      h += '<tr><td class="ip">' + flag(b.cc, b.country, b.ip) + esc(b.ip) + infoBadge(b) +
        '</td><td class="num">' + esc(b.exp) + '</td><td class="r">' +
        iact("", "Unban", "unban&cat=" + b.cat + "&ip=" + encodeURIComponent(b.ip), "unban") +
        wlAct(b.ip) +
        "</td></tr>";
    });
    return h + "</table>";
  }

  function renderProtection(d) {
    if (d.version) $("verFoot").textContent = "v" + d.version;
    if (d.refresh !== undefined) REFRESH = d.refresh;   // honor the setting on direct #protection loads
    var h;
    if (d.candidates.length) {
      h = "<table><tr><th>IP</th><th>SYN/min</th><th>ports</th><th></th></tr>";
      d.candidates.forEach(function (c) {
        h += '<tr><td class="ip">' + flag(c.cc, c.country, c.ip) + esc(c.ip) + infoBadge(c) +
          '</td><td class="num">' + c.synmin + '</td><td class="num">' + esc(c.ports) + '</td><td class="r">' +
          wlAct(c.ip) +
          iact("danger", "Ban", "ban&cat=closed&ip=" + encodeURIComponent(c.ip), "ban") +
          "</td></tr>";
      });
      h += "</table>";
    } else h = '<div class="empty">Quiet — nobody approaching the ban threshold.</div>';
    $("candBox").innerHTML = h;

    [["closed", d.closed, d.closedn], ["open", d.open, d.openn]].forEach(function (row) {
      var cat = row[0], items = row[1], shown = items.length;
      // total = the true set size (the payload caps the rows it ships); fall back
      // to shown for older payloads that don't send the count
      var total = row[2] == null ? shown : row[2];
      $(cat + "Cnt").textContent = total;
      $(cat + "All").hidden = total === 0;
      $(cat + "All").setAttribute("data-act", "unban&cat=" + cat + "&ip=ALLCAT");
      $(cat + "All").setAttribute("data-confirm", "Unban the whole category (" + total + ")?");
      var h = total ? banRows(items) : '<div class="empty">Empty.</div>';
      if (total > shown) h += '<div class="capnote">showing ' + shown + ' of ' + total + ' — use “unban all” to clear the rest</div>';
      $(cat + "Box").innerHTML = h;
    });
  }

  function renderWhitelist(d) {
    if (d.version) $("verFoot").textContent = "v" + d.version;
    if (d.refresh !== undefined) REFRESH = d.refresh;   // honor the setting on direct #whitelist loads
    var h;
    if (d.items.length) {
      h = '<table><tr><th>IP / subnet</th><th>note</th><th title="Time since the most recent packet from this address (from conntrack)">last seen</th><th></th></tr>';
      d.items.forEach(function (w) {
        h += '<tr><td class="ip">' + flag(w.cc, w.country, w.ip) + esc(w.ip) + infoBadge(w) +
          '</td><td class="note" data-ip="' + esc(w.ip) + '" title="Click to edit the note">' +
          (w.note ? esc(w.note) : '<span class="addnote">' + IC.pen + "</span>") +
          '</td><td class="num">' + esc(w.last) + '</td><td class="r">' +
          iact("danger", "Remove", "unwhite&ip=" + encodeURIComponent(w.ip), "trash") +
          "</td></tr>";
      });
      h += "</table>";
    } else h = '<div class="empty">Empty.</div>';
    $("wlBox").innerHTML = h;
  }

  // rebuild the WAN <select> from the interfaces the router reported, keeping the
  // configured one selected. The backend always includes the current WAN in the
  // list, but fall back to injecting it if the payload ever arrives without it so
  // the field never renders empty and silently drops the setting on Apply.
  function fillIfaces(sel, list, cur) {
    list = list || [];
    var opts = "", i, have = false;
    for (i = 0; i < list.length; i++) {
      have = have || list[i] === cur;
      opts += '<option value="' + esc(list[i]) + '">' + esc(list[i]) + "</option>";
    }
    if (!have && cur) opts += '<option value="' + esc(cur) + '">' + esc(cur) + " (down)</option>";
    sel.innerHTML = opts;
    sel.value = cur;
  }

  function renderSettings(d) {
    REFRESH = d.config.refresh;
    $("verFoot").textContent = "v" + d.version;
    // don't stomp on values mid-edit: while focus is in the form, or while there
    // are unsaved changes (a toggle/segment click leaves no focused input, so the
    // focus test alone would let auto-refresh revert them before Apply)
    var f = $("cfgForm");
    if (!f.contains(document.activeElement) && !CFG_DIRTY) {
      f.ttlh.value = d.config.ttlh; f.refresh.value = d.config.refresh;
      fillIfaces(f.wan, d.ifaces, d.config.wan);
      f.burst.value = d.config.burst; f.svcports.value = d.config.svcports;
      f.svcburst.value = d.config.svcburst; f.synto.value = d.config.synto;
      f.tclosed.checked = d.config.tclosed; f.topen.checked = d.config.topen;
      f.tsubnet.checked = d.config.tsubnet; f.snmask.value = d.config.snmask;
      f.snburst.value = d.config.snburst; f.tban.checked = d.config.tban;
      f.torban.checked = d.config.torban;
      var rjb = $("rejectseg").querySelectorAll("button[data-reject-val]");
      for (var ri = 0; ri < rjb.length; ri++)
        rjb[ri].classList.toggle("on", rjb[ri].getAttribute("data-reject-val") === (d.config.reject ? "reject" : "drop"));
      f.compact.checked = d.config.compact; f.compactpct.value = d.config.compactpct;
      f.compactevery.value = d.config.compactevery;
      syncDeps(f);
    }
    BANIPS = { scan: d.banscan || [], flood: d.banflood || [] };
    foldPreview();
    // database status subtitles: "N unit · updated date" or the not-downloaded hint
    function dbSub(id, rows, unit, date, empty) {
      $(id).textContent = rows ? rows + " " + unit + " · updated " + (date || "recently") : empty;
    }
    dbSub("geoSub", d.geo.rows, "ranges",      d.geo.date, "Not downloaded yet · dbip-country lite (free).");
    dbSub("asnSub", d.asn.rows, "ranges",      d.asn.date, "Not downloaded yet · dbip-asn lite (free).");
    dbSub("torSub", d.tor.rows, "exit relays", d.tor.date, "Not downloaded yet · torproject.org bulk exit list (free).");
    // threat carries an extra "categorised" count, so it stays bespoke
    $("threatSub").textContent = d.threat.rows
      ? d.threat.rows + " flagged · " + (d.threat.act ? d.threat.act + " categorised · " : "") +
        "updated " + (d.threat.date || "recently")
      : "Not downloaded yet · IPsum + activity feeds (free).";
    $("autoDb").checked = d.autodb;
    // logging level selector (off / normal / verbose)
    var segb = $("logseg").querySelectorAll("button[data-log-val]");
    for (var i = 0; i < segb.length; i++) segb[i].classList.toggle("on", segb[i].getAttribute("data-log-val") === d.loglevel);
    $("clearBtn").hidden = d.nev === 0;
    var h;
    if (d.nev > 0) {
      h = '<div class="logview">';
      d.events.forEach(function (ev) {
        h += '<div class="logline"><span class="lnum">' + ev.n + '</span><span class="ltime">' + esc(ev.time) +
          '</span> <span class="ltype ty-' + esc(ev.type) + '">' + esc(ev.type) +
          '</span> <span class="ldetail">' + esc(ev.detail) + "</span></div>";
      });
      h += "</div>";
    } else if (d.loglevel === "off") h = '<div class="empty">Logging is off — pick a level above to start recording.</div>';
    else h = '<div class="empty">No events recorded yet.</div>';
    // the auto-refresh rebuilds this box; keep the reader's place in the log
    var oldLv = $("evBox").querySelector(".logview"), st = oldLv ? oldLv.scrollTop : 0;
    $("evBox").innerHTML = h;
    var newLv = $("evBox").querySelector(".logview");
    if (newLv && st) newLv.scrollTop = st;
    // updates
    $("verChip").textContent = "v" + d.update.cur;
    // the page runs the OLD js/css against the new backend after an update —
    // reload once when the reported version changes, making the "refreshes
    // itself" promise actually true
    if (BOOTVER === null) BOOTVER = d.update.cur;
    else if (d.update.cur !== BOOTVER) { location.reload(); return; }
    var u = d.update, hint, ctl = "";
    if (u.state === "updating") {
      hint = "Updating… about a minute, then this page refreshes itself.";
      if (!UPD_POLL) UPD_POLL = setTimeout(function () {
        UPD_POLL = null;
        if (TAB === "settings") loadTab("settings");
      }, 8000);
    } else if (u.lst === "ok") {
      hint = u.latest === u.cur ? "v" + u.latest + " — you are up to date · checked " + u.checked
                                : "v" + u.latest + " is available · checked " + u.checked;
    } else if (u.lst === "err") hint = "Could not reach GitHub at " + u.checked + " — try again.";
    else hint = "Not checked yet.";
    if (u.state && u.state.indexOf("failed") === 0) hint = u.state + " — check tacet-update.log";
    $("updHint").textContent = hint;
    if (u.state !== "updating") {
      ctl = '<a class="btn" href="#" data-act="checkupdate" title="Ask GitHub for the newest release">Check for updates</a>';
      if (u.lst === "ok" && u.latest !== u.cur)
        ctl += ' <a class="btn primary" href="#" data-act="doupdate" data-confirm="Update Tacet v' + esc(u.cur) + " → v" + esc(u.latest) + ' now? Settings and bans are kept." title="Download v' + esc(u.latest) + ' and install it in place">Update to v' + esc(u.latest) + "</a>";
    }
    $("updCtl").innerHTML = ctl;
  }

  // grey out settings rows whose feature toggle (data-dep) is off
  function syncDeps(f) {
    each(document.querySelectorAll("#cfgForm .srow[data-dep]"), function (row) {
      var on = f[row.getAttribute("data-dep")].checked;
      row.classList.toggle("sdim", !on);
      each(row.querySelectorAll("input[type=text]"), function (i) { i.disabled = !on; });
    });
  }

  // live estimate of how many /snmask blocks the fold would collapse right now, at the
  // mask + density currently in the form. Pure client-side arithmetic over the ban list
  // the settings snapshot delivers — recomputed as the user edits, shown even while the
  // feature is off so its effect is visible before enabling. Density scales with the
  // mask, matching the collector's rule (need = ceil(blocksize * pct / 100), min 2).
  function foldPreview() {
    var el = $("compactPrev"); if (!el) return;
    var f = $("cfgForm");
    // only while the feature is on — no point estimating a fold that won't run
    if (!f.compact.checked) { el.textContent = ""; return; }
    var mask = parseInt(f.snmask.value, 10), pct = parseFloat(f.compactpct.value);
    if (!BANIPS || !(mask >= 8 && mask <= 30) || !(pct > 0 && pct <= 100)) { el.textContent = ""; return; }
    var bs = Math.pow(2, 32 - mask), need = Math.ceil(bs * pct / 100); if (need < 2) need = 2;
    // count each surface separately — the fold is per-reason (cnet OR fnet), so a
    // block mixing 8 scanners + 5 flooders does NOT fold even if 13 >= need
    var blocks = 0, folded = 0;
    ["scan", "flood"].forEach(function (set) {
      var grp = {}, k;
      BANIPS[set].forEach(function (ip) {
        var v = ip2int(ip); if (isNaN(v)) return;
        var net = v - (v % bs);
        grp[net] = (grp[net] || 0) + 1;
      });
      for (k in grp) if (grp[k] >= need) { blocks++; folded += grp[k]; }
    });
    // only speak up when there's actually something to fold
    el.textContent = blocks
      ? "≈ " + blocks + (blocks === 1 ? " subnet" : " subnets") + " fold now · −" + (folded - blocks) + " individual bans"
      : "";
  }

  function loadTab(t) {
    if (t === "dash") getJSON("overview", renderDash);
    else if (t === "protection") getJSON("protection", renderProtection);
    else if (t === "whitelist") getJSON("whitelist", renderWhitelist);
    else if (t === "settings") getJSON("settings", renderSettings);
  }

  /* ---------- chart tooltips (delegated — the svgs are rebuilt on refresh) ---------- */
  function initChartTip() {
    var tip = document.createElement("div");
    tip.className = "charttip"; tip.style.display = "none";
    document.body.appendChild(tip);
    function fmt(t) { var d = new Date(t * 1000);
      return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2); }
    function bind(box, build) {
      box.addEventListener("mouseover", function (e) {
        var r = e.target; if (!r.classList || !r.classList.contains("hov")) return;
        tip.innerHTML = "<b>" + fmt(+r.getAttribute("data-t")) + "</b>" + build(r);
        tip.style.display = "block";
      });
      box.addEventListener("mousemove", function (e) {
        // flip to the other side of the cursor when the default spot would
        // push the tip past the viewport (edge buckets of the histogram)
        var de = document.documentElement;
        var x = e.pageX + 14, y = e.pageY + 14;
        if (x + tip.offsetWidth > window.scrollX + de.clientWidth - 8)
          x = Math.max(window.scrollX + 8, e.pageX - tip.offsetWidth - 14);
        if (y + tip.offsetHeight > window.scrollY + de.clientHeight - 8)
          y = Math.max(window.scrollY + 8, e.pageY - tip.offsetHeight - 14);
        tip.style.left = x + "px"; tip.style.top = y + "px";
      });
      box.addEventListener("mouseout", function () { tip.style.display = "none"; });
    }
    bind($("chartBox"), function (r) {
      return '<span class="cc">closed</span>' + r.getAttribute("data-c") +
        '<span class="co">open</span>' + r.getAttribute("data-o");
    });
    bind($("dropsBox"), function (r) {
      return '<span class="cd">dropped</span>' + r.getAttribute("data-v");
    });
  }

  /* ---------- IP details popup (hover or click any info badge) ---------- */
  function initInfoPop() {
    var pop = document.createElement("div");
    pop.className = "ipop"; pop.style.display = "none";
    document.body.appendChild(pop);
    var openT = null, closeT = null;
    function row(k, v, cls) {
      return '<div class="ir"><span class="k">' + k + '</span><span class="v' + (cls || "") + '">' + v + "</span></div>";
    }
    // activity bitmask -> what the address was seen doing (tacet-activity.dat bits)
    var ACTS = [[1, "port scanning"], [2, "brute-force logins"], [4, "mail abuse"],
                [8, "web attacks"], [16, "VoIP fraud"], [32, "botnet C2"]];
    function openFor(badge) {
      // the 300 ms hover debounce may fire after an auto-refresh replaced the row;
      // a detached node's getBoundingClientRect() is all-zeros, pinning the popup
      // to the page corner — bail if the badge is no longer in the document
      if (!document.contains(badge)) return;   // isConnected is Chrome 51+; contains works everywhere
      var n = +badge.getAttribute("data-threat"), a = +badge.getAttribute("data-acts");
      var bad = n > 0 || a > 0;
      var org = badge.getAttribute("data-org"), country = badge.getAttribute("data-country");
      // what it was seen doing, when the categorised feeds know; otherwise fall
      // back to the IPsum listing count; otherwise a plain dash
      var rep = "—";
      if (a > 0) {
        var labels = [];
        ACTS.forEach(function (x) { if (a & x[0]) labels.push(x[1]); });
        rep = labels.join(" · ");
      } else if (n > 0) rep = "On " + n + " abuse blocklists";
      // the note is redundant on the whitelist tab itself — every row there is one
      var wlEntry = badge.closest("#tab-whitelist") ? null : wlHit(badge.getAttribute("data-ip"));
      pop.innerHTML =
        '<div class="ip-t' + (bad ? " bad" : "") + '">' + esc(badge.getAttribute("data-ip")) + "</div>" +
        row("Owner", org ? esc(org) : "—") +
        row("Country", country ? esc(country) : "—") +
        row("Reputation", rep, bad ? " bad" : "") +
        (wlEntry ? row("Whitelist", esc(wlEntry), " good") : "");
      var r = badge.getBoundingClientRect(), vw = document.documentElement.clientWidth;
      pop.style.display = "block";
      var left = Math.min(r.left + window.scrollX, window.scrollX + vw - pop.offsetWidth - 8);
      pop.style.left = Math.max(8, left) + "px";
      pop.style.top = (r.bottom + window.scrollY + 6) + "px";
    }
    function hide() { pop.style.display = "none"; }
    document.addEventListener("click", function (e) {
      var badge = e.target.closest && e.target.closest(".ibadge");
      if (badge) { e.preventDefault(); clearTimeout(openT); openFor(badge); return; }
      // any click outside the popup closes it
      if (!e.target.closest(".ipop")) hide();
    });
    // hovering a badge opens the popup too (debounced, so a pass-over doesn't
    // flash it); hovering the popup itself keeps it open so its text is selectable
    document.addEventListener("mouseover", function (e) {
      var badge = e.target.closest && e.target.closest(".ibadge");
      if (badge) {
        clearTimeout(closeT); clearTimeout(openT);
        openT = setTimeout(function () { openFor(badge); }, 300);
        return;
      }
      if (e.target.closest && e.target.closest(".ipop")) clearTimeout(closeT);
    });
    document.addEventListener("mouseout", function (e) {
      if (e.target.closest && (e.target.closest(".ibadge") || e.target.closest(".ipop"))) {
        clearTimeout(openT);
        closeT = setTimeout(hide, 250);
      }
    });
  }

  /* ---------- settings left menu ---------- */
  function initSettings() {
    var menu = document.querySelectorAll(".smenu a[data-sec]");
    var secs = document.querySelectorAll(".ssec");
    var apply = document.querySelector(".sfoot");   // the Apply footer (right-aligned)
    function show(sec) {
      var i;
      for (i = 0; i < menu.length; i++) menu[i].classList.toggle("on", menu[i].getAttribute("data-sec") === sec);
      for (i = 0; i < secs.length; i++) secs[i].style.display = secs[i].getAttribute("data-sec") === sec ? "" : "none";
      if (apply) apply.style.display = (sec === "logging" || sec === "databases" || sec === "updates" || sec === "transfer") ? "none" : "";
      lsSet("tacet-sec", sec)
    }
    for (var k = 0; k < menu.length; k++) menu[k].addEventListener("click", function (e) {
      e.preventDefault(); show(this.getAttribute("data-sec"));
    });
    var saved = lsGet("tacet-sec");
    if (saved === "geo") saved = "databases";   // section renamed in 1.4
    var valid = false;
    for (var m = 0; m < menu.length; m++) if (menu[m].getAttribute("data-sec") === saved) valid = true;
    show(valid ? saved : "general");
  }

  /* ---------- chart-scale segmented picker ---------- */
  function initScaleSeg() {
    var seg = $("scaleseg");
    if (!seg) return;
    var btns = seg.querySelectorAll("button[data-scale-val]");
    function mark(v) { for (var i = 0; i < btns.length; i++) btns[i].classList.toggle("on", btns[i].getAttribute("data-scale-val") === v); }
    mark(scaleNow());
    for (var i = 0; i < btns.length; i++) btns[i].addEventListener("click", function () {
      lsSet(SKEY, this.getAttribute("data-scale-val")); mark(scaleNow());
      if (TAB === "dash") loadTab("dash");   // redraw the charts right away
    });
  }

  /* ---------- color-scheme segmented picker ---------- */
  function initThemeSeg() {
    var seg = $("themeseg");
    if (!seg) return;
    var btns = seg.querySelectorAll("button[data-theme-val]");
    function mark(v) { for (var i = 0; i < btns.length; i++) btns[i].classList.toggle("on", btns[i].getAttribute("data-theme-val") === v); }
    mark(themeNow());
    for (var i = 0; i < btns.length; i++) btns[i].addEventListener("click", function () {
      var v = this.getAttribute("data-theme-val");
      lsSet(TKEY, v); applyTheme(v); mark(v);
    });
  }

  /* ---------- boot ---------- */
  function onReady() {
    // fill the static icon placeholders
    each(document.querySelectorAll("[data-ic]"), function (el) {
      el.innerHTML = IC[el.getAttribute("data-ic")] + el.innerHTML;
    });
    // delegated actions: any element with data-act
    document.addEventListener("click", function (e) {
      var el = e.target.closest ? e.target.closest("[data-act]") : null;
      if (!el) return;
      e.preventDefault();
      act(el.getAttribute("data-act"), el.getAttribute("data-confirm"));
    });
    // toggles & buttons
    $("masterSw").addEventListener("click", function (e) { e.preventDefault(); act("master"); });
    var lsb = $("logseg").querySelectorAll("button[data-log-val]");
    for (var li = 0; li < lsb.length; li++) lsb[li].addEventListener("click", function () {
      act("loglevel&lvl=" + this.getAttribute("data-log-val"));
    });
    $("clearBtn").addEventListener("click", function (e) { e.preventDefault(); act("clearlog", "Clear the event log?"); });
    // database "Update" buttons — same shape, only the endpoint and size differ
    [["geoBtn",    "geoupdate",    "the IP→country database now? ~11 MB"],
     ["threatBtn", "threatupdate", "the threat list now? ~2 MB"],
     ["asnBtn",    "asnupdate",    "the ASN database now? ~23 MB"],
     ["torBtn",    "torupdate",    "the Tor exit-relay list now? ~100 KB"]
    ].forEach(function (b) {
      $(b[0]).addEventListener("click", function (e) {
        e.preventDefault(); act(b[1], "Download " + b[2] + ", runs in the background.");
      });
    });
    // backup: the selected sections become an inc= list; the CGI answers with a
    // Content-Disposition download, so plain navigation is enough
    $("expBtn").addEventListener("click", function (e) {
      e.preventDefault();
      var inc = [];
      if ($("expConfig").checked) inc.push("config");
      if ($("expWl").checked) inc.push("whitelist");
      if ($("expBans").checked) inc.push("bans");
      if (!inc.length) { $("expHint").textContent = "Nothing selected."; return; }
      $("expHint").textContent = "";
      location.href = "/api.cgi?fn=export&inc=" + inc.join(",");
    });
    // custom file picker: our button proxies the hidden native input, the
    // name line under it echoes the choice
    $("impPick").addEventListener("click", function (e) {
      e.preventDefault(); $("impFile").click();
    });
    $("impFile").addEventListener("change", function () {
      $("impName").textContent = this.files[0] ? this.files[0].name : "No file chosen";
    });
    // restore: read the file in the browser, POST its text; the mode comes from
    // the segmented picker (append adds, override replaces carried sections)
    var impBusy = false;
    $("impBtn").addEventListener("click", function (e) {
      e.preventDefault();
      if (impBusy) return;   // one restore at a time — two concurrent imports race server-side
      var file = $("impFile").files[0];
      if (!file) { $("impHint").textContent = "Choose a file first."; return; }
      var mode = $("impseg").querySelector("button.on").getAttribute("data-imp-val");
      if (mode === "override" && !confirm("Override: every section present in the file will REPLACE the current data. Continue?")) return;
      impBusy = true; $("impBtn").classList.add("disabled");
      $("impHint").textContent = "Restoring…";
      // FileReader, not file.text(): Blob.text() is much newer (Safari 14+) than
      // anything else this file uses — on older browsers it threw synchronously
      // AFTER impBusy was set, wedging the Restore button until a page reload
      new Promise(function (res, rej) {
        var rd = new FileReader();
        rd.onload = function () { res(String(rd.result)); };
        rd.onerror = function () { rej(rd.error); };
        rd.readAsText(file);
      }).then(function (txt) {
        return fetch("/api.cgi?fn=import&mode=" + mode, { method: "POST", body: txt, cache: "no-store" });
      }).then(function (r) { return r.json(); }).then(function (j) {
        if (j && j.ok) {
          $("impHint").textContent = "Restored: " + j.config + " settings · " + j.wl + " whitelist entries · " + j.bans + " bans.";
          $("impFile").value = "";
          $("impName").textContent = "No file chosen";
          loadTab("settings");
        } else $("impHint").textContent = "Failed: " + ((j && j.err) || "unknown error") + ".";
      }).catch(function () { $("impHint").textContent = "Failed: network error."; })
        .then(function () { impBusy = false; $("impBtn").classList.remove("disabled"); });
    });
    $("autoDb").addEventListener("change", function () {
      // autodb is a server-side TOGGLE: if the request is lost the checkbox and
      // the server invert against each other — revert the box on failure so the
      // next click toggles from the state the server actually has
      var box = this;
      act("autodb", null, function (j) { if (!j || j.ok === false) box.checked = !box.checked; });
    });
    // forms
    $("banForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var f = this;
      // clear the field only once the server confirms, so a rejected entry
      // stays visible for correction instead of silently disappearing
      act("ban&cat=closed&ip=" + encodeURIComponent(f.ip.value.trim()), null, function (j) {
        if (j && j.ok !== false) f.ip.value = "";
        else if (j && j.err !== "whitelisted") alert("Not banned: " + ((j && j.err) || "invalid address") + ".");
      });
    });
    $("wlForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var f = this;
      // one field: the address, then an optional free-text note after a space
      var v = f.ip.value.trim(), sp = v.indexOf(" ");
      var ip = sp < 0 ? v : v.slice(0, sp), note = sp < 0 ? "" : v.slice(sp + 1).trim();
      var q = "white&ip=" + encodeURIComponent(ip);
      if (note) q += "&note=" + encodeURIComponent(note);
      act(q, null, function (j) {
        if (j && j.ok !== false) f.ip.value = "";
        else if (j) alert("Not whitelisted: " + (j.err || "invalid address") + ".");
      });
    });
    // whitelist notes: clicking the note cell swaps in an inline editor.
    // Enter or blur saves (empty text clears the note), Esc cancels.
    $("wlBox").addEventListener("click", function (e) {
      var td = e.target.closest && e.target.closest("td.note");
      if (!td || td.querySelector("input")) return;
      var ip = td.getAttribute("data-ip");
      var cur = td.querySelector(".addnote") ? "" : td.textContent;
      td.innerHTML = '<input class="noteedit" type="text" maxlength="96">';
      var inp = td.querySelector("input");
      inp.value = cur; inp.focus(); inp.select();
      var done = false;
      function save() {
        if (done) return; done = true;
        act("setnote&ip=" + encodeURIComponent(ip) + "&note=" + encodeURIComponent(inp.value.trim()));
      }
      inp.addEventListener("keydown", function (ev) {
        // ev.key is Chrome 51+ — older engines get undefined and Escape would
        // silently fall through to the blur SAVE of an abandoned edit; keep the
        // keyCode fallback (13/27, "Esc" on old IE/Edge)
        var k = ev.key || ev.keyCode;
        if (k === "Enter" || k === 13) { ev.preventDefault(); save(); }
        else if (k === "Escape" || k === "Esc" || k === 27) { done = true; loadTab(TAB); }
      });
      inp.addEventListener("blur", save);
    });
    $("cfgForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var f = this, q = "config";
      ["ttlh", "refresh", "wan", "burst", "svcports", "svcburst", "synto", "snmask", "snburst", "compactpct", "compactevery"].forEach(function (n) {
        q += "&" + n + "=" + encodeURIComponent(f[n].value.trim());
      });
      if (f.tclosed.checked) q += "&tclosed=on";
      if (f.topen.checked) q += "&topen=on";
      if (f.tsubnet.checked) q += "&tsubnet=on";
      if (f.tban.checked) q += "&tban=on";
      if (f.torban.checked) q += "&torban=on";
      if ($("rejectseg").querySelector('button.on[data-reject-val="reject"]')) q += "&reject=on";
      if (f.compact.checked) q += "&compact=on";
      // visible feedback: the save is instant, so flash the button through
      // Saving… → Saved (green) → back, and guard against a double-submit
      var btn = f.querySelector(".sapply");
      if (btn.disabled) return;
      btn.disabled = true; btn.classList.remove("ok"); btn.textContent = "Saving…";
      act(q, null, function (j) {
        // j: {ok:true} saved · {ok:false} rejected values · null network failure
        var okr = !!j && j.ok !== false;
        if (okr) CFG_DIRTY = false;   // saved — auto-refresh may repaint again
        btn.textContent = okr ? "Saved" : (j ? "Check values" : "Failed");
        btn.classList.toggle("ok", okr);
        setTimeout(function () {
          btn.textContent = "Apply changes"; btn.classList.remove("ok"); btn.disabled = false;
        }, okr ? 1400 : 2000);
      });
    });
    // any edit to a config control marks the form dirty, so auto-refresh won't
    // revert unsaved changes (checkbox/segment clicks don't leave a focused input)
    $("cfgForm").addEventListener("input", function () { CFG_DIRTY = true; });
    $("cfgForm").addEventListener("change", function () { CFG_DIRTY = true; });
    $("rejectseg").addEventListener("click", function () { CFG_DIRTY = true; });
    // form-local segmented pickers: clicking marks the choice, submit reads ".on"
    function segButtons(id) {
      var b = $(id).querySelectorAll("button");
      for (var i = 0; i < b.length; i++) b[i].addEventListener("click", function () {
        for (var j = 0; j < b.length; j++) b[j].classList.toggle("on", b[j] === this);
      });
    }
    segButtons("rejectseg");   // banned-traffic policy, committed by Apply changes
    segButtons("impseg");      // restore mode, read by the Restore button
    // feature toggles dim their dependent rows live
    var cfgf = $("cfgForm");
    ["tclosed", "topen", "tsubnet", "compact"].forEach(function (n) {
      cfgf[n].addEventListener("change", function () { syncDeps(cfgf); });
    });
    // fold preview recomputes as the mask or density is edited, and appears/clears
    // with the toggle (it's hidden while the feature is off)
    ["snmask", "compactpct"].forEach(function (n) {
      cfgf[n].addEventListener("input", foldPreview);
    });
    cfgf.compact.addEventListener("change", foldPreview);
    // tabs
    window.addEventListener("hashchange", function () { showTab(currentHashTab()); });
    initChartTip();
    initInfoPop();
    initSettings();
    initThemeSeg();
    initScaleSeg();
    showTab(currentHashTab());
    // auto-refresh: refetch the active tab; pause while typing or in background
    setInterval(function () {
      // a missing/NaN refresh (version-skewed payload) must not turn this into a
      // 1 Hz fetch loop — treat anything non-positive or non-finite as "off"
      if (!(REFRESH > 0) || document.hidden) return;
      var el = document.activeElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA")) return;
      if (CFG_DIRTY) return;   // don't stomp unsaved settings edits (see below)
      if ((Date.now() - LASTLOAD) / 1000 < REFRESH) return;
      loadTab(TAB);
      LASTLOAD = Date.now();
    }, 1000);
  }
  var LASTLOAD = Date.now();
  // re-stamp on every load so the interval measures from the last fetch
  var _load = loadTab;
  loadTab = function (t) { LASTLOAD = Date.now(); _load(t); };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", onReady);
  else onReady();
})();
