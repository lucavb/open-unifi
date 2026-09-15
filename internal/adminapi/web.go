package adminapi

import (
	"io"
	"net/http"
)

// page serves the embedded single-file web console at "/". It is the exact
// content of ../web/static/index.html, inlined as a Go string constant:
// //go:embed cannot cross package directories, and inlining keeps the admin
// binary dependency-free while web/static remains the readable reference
// copy (keep the two in sync when editing).

func page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, indexHTML)
}

// indexHTML mirrors web/static/index.html byte for byte.
const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>open-unifi controller</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ccircle cx='8' cy='8' r='7' fill='%232563eb'/%3E%3Ccircle cx='8' cy='8' r='3' fill='white'/%3E%3C/svg%3E">
<style>
  :root {
    --accent: #2563eb; --accent-hover: #1d4ed8; --accent-soft: #eff6ff;
    --danger: #dc2626; --ok: #16a34a;
    --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0;
    --text: #0f172a; --muted: #64748b;
    --radius: 10px;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  .container { max-width: 980px; margin: 0 auto; padding: 24px 20px 64px; }
  header.top {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding: 16px 20px; margin-bottom: 24px;
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  }
  header.top h1 { font-size: 18px; margin: 0; letter-spacing: -0.01em; }
  header.top .sub { color: var(--muted); font-size: 13px; }
  .spacer { flex: 1; }
  .tokenbox { display: flex; gap: 8px; align-items: center; }
  .tokenbox input { width: 240px; }
  input, select, button {
    font: inherit; color: inherit;
    border: 1px solid var(--border); border-radius: 8px;
    padding: 7px 10px; background: var(--surface);
  }
  input:focus-visible, select:focus-visible, button:focus-visible {
    outline: 2px solid var(--accent); outline-offset: 2px;
  }
  button.btn {
    background: var(--accent); color: #fff; border-color: var(--accent);
    cursor: pointer; transition: background .12s ease, transform .06s ease;
  }
  button.btn:hover { background: var(--accent-hover); }
  button.btn:active { transform: translateY(1px); }
  button.btn-ghost {
    background: var(--accent-soft); color: var(--accent); border-color: transparent;
    cursor: pointer; font-weight: 500;
  }
  button.btn-ghost:hover { background: #dbeafe; }
  button.btn-small { padding: 4px 10px; font-size: 13px; border-radius: 7px; }
  section.card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 20px; margin-bottom: 24px;
  }
  section.card > h2 {
    margin: 0 0 4px; font-size: 15px; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--muted); font-weight: 600;
  }
  section.card > p.hint { margin: 0 0 14px; color: var(--muted); font-size: 13px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th {
    font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--muted); font-weight: 600; border-bottom: 1px solid #cbd5e1;
  }
  tr:last-child > td { border-bottom: none; }
  td input, td select { width: 100%; min-width: 90px; }
  td input.num { width: 90px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
  .badge {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 12px; font-weight: 600; line-height: 1.7;
  }
  .badge.state-1 { background: #fef3c7; color: #b45309; }  /* pending: amber */
  .badge.state-2 { background: #dbeafe; color: #1d4ed8; }  /* adopting: blue */
  .badge.state-3 { background: #dcfce7; color: #15803d; }  /* adopted: green */
  .badge.state-4 { background: #fee2e2; color: #b91c1c; }  /* lost: red */
  .badge.state-unknown { background: #e2e8f0; color: #475569; }
  .badge.live { background: #dcfce7; color: #15803d; }
  .pill {
    display: inline-block; padding: 5px 12px; border-radius: 8px;
    background: #fee2e2; color: #b91c1c; font-size: 13px; margin: 10px 0 0;
  }
  .pill[hidden] { display: none; }
  form.rowform { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  form.rowform input { width: 220px; }
  .actions-cell { white-space: nowrap; text-align: right; }
  footer { color: var(--muted); font-size: 13px; }
  footer a { color: var(--accent); text-decoration: none; }
  footer a:hover { text-decoration: underline; }
  .empty { color: var(--muted); font-style: italic; padding: 10px 0; }
  noscript p { color: #b45309; background: #fef3c7; padding: 10px 14px; border-radius: 8px; }
</style>
</head>
<body>
<div class="container">
  <noscript><p>The admin console needs JavaScript to call the REST API. Enable it, or use the endpoints directly: <span class="mono">GET /api/v1/devices</span>.</p></noscript>

  <header class="top">
    <h1>open-unifi controller</h1>
    <span class="sub" id="whoami">loading&hellip;</span>
    <span class="spacer"></span>
    <div class="tokenbox" id="tokenbox" hidden>
      <label for="token" class="sub">Admin token</label>
      <input type="password" id="token" placeholder="Bearer token" autocomplete="off">
      <button type="button" class="btn btn-small" id="tokenSave">Save</button>
    </div>
  </header>
  <span class="pill" id="globalError" hidden></span>

  <section class="card" id="devSection">
    <h2>Devices</h2>
    <p class="hint">Polled every 5&nbsp;s. State: pending &rarr; adopting &rarr; adopted (green &ldquo;live&rdquo; badge) &rarr; lost.</p>
    <table aria-label="Devices">
      <thead><tr><th>MAC</th><th>Name</th><th>Model</th><th>IP</th><th>State</th><th>Power</th><th></th></tr></thead>
      <tbody id="devRows"></tbody>
    </table>
    <span class="pill" id="devError" hidden></span>
  </section>

  <section class="card" id="pendingSection">
    <h2>Adopt candidates</h2>
    <p class="hint">Devices heard on the discovery channel but not yet adopted.</p>
    <div id="pendingRows"></div>
    <span class="pill" id="pendingError" hidden></span>
  </section>

  <section class="card" id="addSection">
    <h2>Add manually</h2>
    <p class="hint">Register a device MAC on the adopt whitelist (state: pending) even before it shows up on discovery.</p>
    <form class="rowform" id="addForm">
      <input id="addMac" name="mac" placeholder="MAC, e.g. F0-9F-C2-84-8F-2A" required>
      <input id="addName" name="name" placeholder="Optional name (e.g. office-ceiling)">
      <button type="submit" class="btn">Add device</button>
    </form>
    <span class="pill" id="addError" hidden></span>
  </section>

  <section class="card" id="wlSection">
    <h2>Wireless / VLAN config</h2>
    <p class="hint">
      Whole-document editor: <span class="mono">Save</span> PUTs all rows to
      <span class="mono">/api/v1/wireless</span>. Passphrase &ge; 8 chars unless security is
      &ldquo;open&rdquo;; VLAN 1&ndash;4094.
    </p>
    <table aria-label="Wireless networks">
      <thead><tr><th>SSID</th><th>Name</th><th>Security</th><th>Passphrase</th><th>VLAN</th><th>On</th><th></th></tr></thead>
      <tbody id="wlRows"></tbody>
      <tfoot><tr><td colspan="7"><button type="button" class="btn-ghost btn-small" id="wlAddRow">+ Row</button>&nbsp; <button type="button" class="btn btn-small" id="wlSave">Save</button></td></tr></tfoot>
    </table>
    <span class="pill" id="wlError" hidden></span>
  </section>

  <footer>
    Endpoints: <a href="/api/v1/devices">/api/v1/devices</a> &middot;
    <a href="/api/v1/pending">/api/v1/pending</a> &middot;
    <a href="/api/v1/wireless">/api/v1/wireless</a> &middot;
    <a href="/metrics">/metrics</a> &middot;
    <a href="/healthz">/healthz</a>
  </footer>
</div>

<script>
(function () {
  "use strict";

  var stateNames = {
    1: ["pending", "state-1"],
    2: ["adopting", "state-2"],
    3: ["adopted", "state-3"],
    4: ["lost", "state-4"]
  };

  var tokenInput = document.getElementById("token");
  var tokenBox = document.getElementById("tokenbox");

  function showToken(msg) {
    tokenBox.hidden = false;
    if (msg) {
      var el = document.getElementById("whoami");
      el.textContent = msg;
    }
    tokenInput.focus();
  }

  function getJSON(res) {
    return res.json().then(function (body) {
      if (body && typeof body.error === "string") { throw new Error(body.error); }
      return body;
    }, function () { throw new Error("HTTP " + res.status + " (unparseable body)"); });
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    var t = window.sessionStorage.getItem("ou_token");
    if (t) { opts.headers["Authorization"] = "Bearer " + t; }
    return window.fetch(path, opts).then(function (res) {
      if (res.status === 401) {
        window.sessionStorage.removeItem("ou_token");
        showToken("401 unauthorized \u2014 enter the admin token");
        throw new Error("unauthorized (401)");
      }
      if (!res.ok) {
        return getJSON(res).then(function () {
          throw new Error("HTTP " + res.status);
        });
      }
      return res;
    });
  }

  function setError(id, msg) {
    var el = document.getElementById(id);
    if (!msg) { el.hidden = true; el.textContent = ""; return; }
    el.textContent = msg;
    el.hidden = false;
  }

  function badgeFor(state) {
    var info = stateNames[state];
    if (!info) { return '<span class="badge state-unknown">unknown (' + state + ")</span>"; }
    return '<span class="badge ' + info[1] + '">' + info[0] + "</span>";
  }

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function renderDevices(devices) {
    var tbody = document.getElementById("devRows");
    if (!devices.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">no devices registered</td></tr>';
      return;
    }
    var rows = [];
    devices.forEach(function (d) {
      var power = d.state === 3
        ? '<span class="badge live">live</span>'
        : '<span class="sub">&ndash;</span>';
      rows.push(
        "<tr><td class=\"mono\">" + esc(d.mac) + "</td>" +
        "<td>" + esc(d.name || "") + "</td>" +
        "<td>" + esc(d.model || "") + "</td>" +
        "<td class=\"mono\">" + esc(d.ip || "") + "</td>" +
        "<td>" + badgeFor(d.state) + "</td>" +
        "<td>" + power + "</td>" +
        '<td class="actions-cell"><button type="button" class="btn-ghost btn-small" data-del="' + esc(d.mac) + '">Forget</button></td></tr>'
      );
    });
    tbody.innerHTML = rows.join("");
    tbody.querySelectorAll("button[data-del]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        setError("devError", "");
        api("/api/v1/devices/" + encodeURIComponent(btn.getAttribute("data-del")), { method: "DELETE" })
          .then(refreshAll)
          .catch(function (e) { setError("devError", "forget failed: " + e.message); });
      });
    });
  }

  function renderPending(items) {
    var box = document.getElementById("pendingRows");
    if (!items.length) {
      box.innerHTML = '<div class="empty">no candidates on the discovery channel</div>';
      return;
    }
    var rows = ['<table><tbody>'];
    items.forEach(function (p) {
      rows.push(
        "<tr><td class=\"mono\">" + esc(p.mac) + "</td>" +
        "<td>" + esc(p.source || "") + "</td>" +
        '<td class="actions-cell"><button type="button" class="btn btn-small" data-adopt="' + esc(p.mac) + '">Adopt</button></td></tr>'
      );
    });
    rows.push("</tbody></table>");
    box.innerHTML = rows.join("");
    box.querySelectorAll("button[data-adopt]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        setError("pendingError", "");
        api("/api/v1/pending/" + encodeURIComponent(btn.getAttribute("data-adopt")) + "/adopt", { method: "POST" })
          .then(refreshAll)
          .catch(function (e) { setError("pendingError", "adopt failed: " + e.message); });
      });
    });
  }

  function wlanRowInputs(w) {
    var sec = w.security || "wpa-p";
    return '<td><input name="ssid" value="' + esc(w.ssid || "") + '"></td>' +
      '<td><input name="name" value="' + esc(w.name || "") + '"></td>' +
      '<td><select name="security">' +
      ["open", "wpa-p", "wpa-eap"].map(function (s) {
        return '<option value="' + s + '"' + (s === sec ? " selected" : "") + ">" + s + "</option>";
      }).join("") +
      "</select></td>" +
      '<td><input name="passphrase" type="password" value="' + esc(w.passphrase || "") + '"></td>' +
      '<td><input name="vlan" class="num" type="number" min="1" max="4094" value="' + (w.vlan || 1) + '"></td>' +
      '<td><input name="enabled" type="checkbox"' + (w.enabled ? " checked" : "") + "></td>" +
      '<td class="actions-cell"><button type="button" class="btn-ghost btn-small" data-rm>&times;</button></td>';
  }

  function addWlanRow(w) {
    var tr = document.createElement("tr");
    tr.innerHTML = wlanRowInputs(w || { security: "wpa-p", vlan: 1 });
    tr.querySelector("[data-rm]").addEventListener("click", function () { tr.remove(); });
    document.getElementById("wlRows").appendChild(tr);
  }

  function renderWireless(env) {
    var tbody = document.getElementById("wlRows");
    tbody.innerHTML = "";
    (env.wlans || []).forEach(function (w) { addWlanRow(w); });
    if (!tbody.children.length) { addWlanRow({ security: "wpa-p", vlan: 1 }); }
  }

  function validateWlan(w) {
    if (["open", "wpa-p", "wpa-eap"].indexOf(w.security) < 0) { return "bad security"; }
    if (!w.ssid || w.ssid.length > 32) { return "ssid must be 1..32 characters"; }
    if (w.vlan < 1 || w.vlan > 4094) { return "vlan must be 1..4094"; }
    if (w.security === "open") {
      if (w.passphrase) { return "passphrase must be empty when security is open"; }
      return "";
    }
    if (w.passphrase.length < 8) { return "passphrase must be at least 8 characters (" + w.ssid + ")"; }
    return "";
  }

  function collectWireless() {
    var wlans = [];
    var err;
    document.querySelectorAll("#wlRows tr").forEach(function (tr, i) {
      var g = function (n) { return tr.querySelector("[name=" + n + "]"); };
      var w = {
        ssid: g("ssid").value.trim(),
        name: g("name").value.trim(),
        security: g("security").value,
        passphrase: g("passphrase").value,
        vlan: parseInt(g("vlan").value, 10) || 0,
        enabled: g("enabled").checked
      };
      if (!err) {
        err = validateWlan(w);
        if (err) { err = "row " + (i + 1) + ": " + err; }
      }
      wlans.push(w);
    });
    return err ? { error: err } : { wlans: wlans };
  }

  function refreshAll() {
    return api("/api/v1/whoami")
      .then(getJSON)
      .then(function (me) {
        document.getElementById("whoami").textContent =
          "server: " + me.server + " " + me.version +
          (me.authConfigured ? " \u00b7 auth enabled" : " \u00b7 no auth");
        if (me.authConfigured && !window.sessionStorage.getItem("ou_token")) { showToken(""); }
      })
      .catch(function (e) { if (e.message.indexOf("401") < 0) { setError("globalError", e.message); } })
      .then(function () { return api("/api/v1/devices").then(getJSON); })
      .then(function (env) { renderDevices(env.devices || []); setError("devError", ""); })
      .catch(function (e) { setError("devError", "devices: " + e.message); })
      .then(function () { return api("/api/v1/pending").then(getJSON); })
      .then(function (env) { renderPending(env.pending || []); setError("pendingError", ""); })
      .catch(function (e) { setError("pendingError", "pending: " + e.message); })
      .then(function () { return api("/api/v1/wireless").then(getJSON); })
      .then(renderWireless)
      .catch(function (e) { setError("wlError", "wireless: " + e.message); });
  }

  document.getElementById("addForm").addEventListener("submit", function (ev) {
    ev.preventDefault();
    setError("addError", "");
    var body = { mac: document.getElementById("addMac").value, name: document.getElementById("addName").value };
    api("/api/v1/devices", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function () {
        document.getElementById("addMac").value = "";
        document.getElementById("addName").value = "";
        return refreshAll();
      })
      .catch(function (e) { setError("addError", "add failed: " + e.message); });
  });

  document.getElementById("wlAddRow").addEventListener("click", function () { addWlanRow(null); });

  document.getElementById("wlSave").addEventListener("click", function () {
    setError("wlError", "");
    var env = collectWireless();
    if (env.error) { setError("wlError", env.error); return; }
    api("/api/v1/wireless", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) })
      .then(getJSON)
      .then(renderWireless)
      .catch(function (e) { setError("wlError", "save failed: " + e.message); });
  });

  document.getElementById("tokenSave").addEventListener("click", function () {
    var t = tokenInput.value.replace(/^Bearer\s+/i, "");
    window.sessionStorage.setItem("ou_token", t);
    refreshAll();
  });
  tokenInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") { document.getElementById("tokenSave").click(); }
  });

  refreshAll();
  window.setInterval(refreshAll, 5000);
})();
</script>
</body>
</html>
`
