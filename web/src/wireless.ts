// Wireless-side pure helpers: the RADIUS text round-trip, the row-state
// mapping (with §12 accounting preservation), the server-validated field
// rules (message text verbatim — the console pre-validates with the same
// words the API answers with), and the save-collect.
import type { RadiusServer, Wlan, WlanAccounting, WlanRowPayload, WlanRowState } from "./types";

/** The WLAN security options the admin API accepts. */
export const SECS: readonly string[] = ["open", "wpa-p", "wpa3-p", "wpa2-wpa3", "wpa-eap"];

/** The dynamic-VLAN mode options ("" = off, rendered "dynamic vlan: off"). */
export const RADIUS_MODES: readonly string[] = ["", "disabled", "optional", "required"];

let rowClientSequence = 0;
function newRowClientId(): string {
  rowClientSequence += 1;
  return "wlan-row-" + rowClientSequence;
}

/** radiusServersText renders the inline RADIUS profile's auth servers back
 *  into the console's compact text form ("ip" or "ip:port", comma-
 *  separated). A host that itself contains colons (an IPv6 literal) is
 *  bracketed when it carries an explicit port — the same "[host]:port"
 *  form parseRadiusServers reads — so a saved IPv6 server with a port
 *  round-trips instead of collapsing into an ambiguous bare host. */
export function radiusServersText(w: Wlan): string {
  return (w.radius_servers || []).map((s) => {
    if (!s.port) {
      return s.ip;
    }
    return s.ip.indexOf(":") === -1 ? s.ip + ":" + s.port : "[" + s.ip + "]:" + s.port;
  }).join(", ");
}

/** parseRadiusServers is the inverse: "host:port" applies only to a
 *  SINGLE-colon token with an all-digit tail (an IPv6 literal like fd00::5
 *  keeps its colons and parses whole), "[host]:port" (and bare "[host]")
 *  brackets an IPv6 literal that carries an explicit port; anything else
 *  is a bare host with the 1812 default port. */
export function parseRadiusServers(text: string): RadiusServer[] {
  return String(text)
    .split(",")
    .map((part): RadiusServer | null => {
      part = part.trim();
      if (!part) {
        return null;
      }
      if (part.charAt(0) === "[") {
        const close = part.indexOf("]");
        if (close > 1) {
          const tail = part.slice(close + 1);
          if (tail === "") {
            return { ip: part.slice(1, close), port: 0 };
          }
          if (tail.charAt(0) === ":" && /^\d{1,5}$/.test(tail.slice(1))) {
            return { ip: part.slice(1, close), port: parseInt(tail.slice(1), 10) };
          }
        }
      }
      const cut = part.lastIndexOf(":");
      if (cut > 0 && part.indexOf(":") === cut && /^\d{1,5}$/.test(part.slice(cut + 1))) {
        return { ip: part.slice(0, cut), port: parseInt(part.slice(cut + 1), 10) };
      }
      return { ip: part, port: 0 };
    })
    .filter((s): s is RadiusServer => s !== null && s.ip !== "");
}

/** validateWlan pre-checks one collected row with the server's messages,
 *  verbatim (the admin API answers with the same words). */
export function validateWlan(w: WlanRowPayload): string {
  if (SECS.indexOf(w.security) < 0) {
    return "bad security";
  }
  if (!w.ssid || w.ssid.length > 32) {
    return "ssid must be 1..32 characters";
  }
  if (!Number.isInteger(w.vlan) || w.vlan < 1 || w.vlan > 4094) {
    return "vlan must be a whole number from 1 to 4094";
  }
  if (w.security === "open") {
    if (w.passphrase) {
      return "passphrase must be empty when security is open";
    }
    return "";
  }
  if (w.security === "wpa-eap") {
    if (!w.radius_servers || !w.radius_servers.length) {
      return "wpa-eap requires at least one RADIUS server (" + w.ssid + ")";
    }
    if (w.radius_servers.length > 4) {
      return "radius_servers supports at most 4 entries (" + w.ssid + ")";
    }
    for (let i = 0; i < w.radius_servers.length; i++) {
      const srv = w.radius_servers[i];
      if (!srv.ip) {
        return "radius_servers[" + i + "].ip must not be empty (" + w.ssid + ")";
      }
      if (srv.port && (srv.port < 1 || srv.port > 65535)) {
        return "radius_servers[" + i + "].port must be 1..65535 (" + w.ssid + ")";
      }
    }
    if (!w.radius_secret) {
      return "wpa-eap requires a RADIUS shared secret (" + w.ssid + ")";
    }
    if (w.passphrase && w.passphrase.length < 8) {
      return "passphrase must be at least 8 characters (" + w.ssid + ")";
    }
    return "";
  }
  if (w.passphrase.length < 8) {
    return "passphrase must be at least 8 characters (" + w.ssid + ")";
  }
  return "";
}

/** Parse the editor value without truncating fractional or malformed input. */
export function parseVlan(value: number | string): number | null {
  const raw = String(value).trim();
  if (!/^\d+$/.test(raw)) {
    return null;
  }
  const vlan = Number(raw);
  return Number.isInteger(vlan) && vlan >= 1 && vlan <= 4094 ? vlan : null;
}

/** rowFromWlan builds the per-row console state from a WLAN record.
 *  Keep server-controlled identity/band/DAS fields and the non-editable
 *  accounting block in the row state so edits do not erase accepted data.
 *  RADIUS and accounting fields are emitted only for WPA-EAP rows, where
 *  the API accepts them; a security change therefore cannot send invalid
 *  fields. */
export function rowFromWlan(w: Wlan): WlanRowState {
  const sec = SECS.indexOf(w.security) >= 0 ? w.security : "wpa-p";
  const row: WlanRowState = {
    clientId: newRowClientId(),
    ssid: w.ssid || "",
    name: w.name || "",
    security: sec,
    passphrase: w.passphrase || "",
    vlan: w.vlan || 1,
    radiusServers: radiusServersText(w),
    radiusSecret: w.radius_secret || "",
    radiusVlanMode: w.radius_vlan_mode || "",
    enabled: !!w.enabled,
    acct: null,
    preserved: {
      ...(w.id !== undefined ? { id: w.id } : {}),
      ...(w.band !== undefined ? { band: w.band } : {}),
      ...(w.radius_das_enabled !== undefined ? { radius_das_enabled: w.radius_das_enabled } : {})
    }
  };
  if (sec === "wpa-eap") {
    const acct: WlanAccounting = {};
    if (w.accounting_enabled !== undefined) acct.accounting_enabled = w.accounting_enabled;
    if (w.acct_servers !== undefined) acct.acct_servers = w.acct_servers.map((server) => ({ ...server }));
    if (w.interim_update_enabled !== undefined) acct.interim_update_enabled = w.interim_update_enabled;
    if (Object.keys(acct).length > 0) row.acct = acct;
  }
  return row;
}

/** The blank row "+ Row" adds (and the one rendered when a device has no
 *  WLANs): security wpa-p, VLAN 1, everything else empty. The explicit
 *  blank fields satisfy the Wlan wire type rowFromWlan consumes. */
export function defaultWlanRow(): WlanRowState {
  return rowFromWlan({ ssid: "", security: "wpa-p", vlan: 1, enabled: false });
}

/** collectWlans gathers the editable rows into the PUT payload, running
 *  the validation over every row (first error, "row N:" prefixed — the
 *  server's own numbering) and re-attaching preserved accounting fields. */
export function collectWlans(
  rows: WlanRowState[]
): { error: string } | { wlans: WlanRowPayload[] } {
  const wlans: WlanRowPayload[] = [];
  let err = "";
  rows.forEach((row, i) => {
    const vlan = parseVlan(row.vlan);
    const w: WlanRowPayload = {
      ...(row.preserved.id !== undefined ? { id: row.preserved.id } : {}),
      ssid: String(row.ssid).trim(),
      name: String(row.name).trim(),
      security: row.security,
      passphrase: row.passphrase,
      // Preserve an invalid value as an invalid sentinel so validateWlan
      // reports it instead of parseInt silently truncating (e.g. 12.5 → 12).
      vlan: vlan ?? 0,
      enabled: row.enabled,
      ...(row.preserved.band !== undefined ? { band: row.preserved.band } : {})
    };
    if (w.security === "wpa-eap") {
      w.radius_servers = parseRadiusServers(row.radiusServers);
      w.radius_secret = row.radiusSecret;
      w.radius_vlan_mode = row.radiusVlanMode;
      if (row.preserved.radius_das_enabled !== undefined) {
        w.radius_das_enabled = row.preserved.radius_das_enabled;
      }
      // Re-attach preserved accounting fields (see rowFromWlan): the
      // console cannot edit them, but a save must keep what the admin
      // API stored. They ride only wpa-eap rows — the server rejects
      // them on any other security, so a security flip drops them.
      if (row.acct) {
        if (row.acct.accounting_enabled !== undefined) w.accounting_enabled = row.acct.accounting_enabled;
        if (row.acct.acct_servers !== undefined) w.acct_servers = row.acct.acct_servers.map((server) => ({ ...server }));
        if (row.acct.interim_update_enabled !== undefined) w.interim_update_enabled = row.acct.interim_update_enabled;
      }
    }
    if (!err) {
      err = validateWlan(w);
      if (err) {
        err = "row " + (i + 1) + ": " + err;
      }
    }
    wlans.push(w);
  });
  return err ? { error: err } : { wlans };
}
