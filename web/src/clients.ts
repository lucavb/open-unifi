// Display helpers for the clients + client event log cards.
import type { AssignmentView, EventView } from "./types";

/** Event keys the log offers (mirroring the official controller's keys) with
 *  the System Log style labels. */
export const EVENT_KINDS: { key: string; label: string }[] = [
  { key: "EVT_WU_Connected", label: "WiFi Client Connected" },
  { key: "EVT_WU_Disconnected", label: "WiFi Client Disconnected" },
  { key: "EVT_WU_Roam", label: "WiFi Client Roamed" },
  { key: "EVT_WU_RoamRadio", label: "WiFi Client Changed Radio" }
];

export function eventLabel(key: string): string {
  return EVENT_KINDS.find((k) => k.key === key)?.label ?? key;
}

/** "02 Oct 2026, 14:03:05" in the browser's locale/timezone. */
export function dateTimeText(ms: number): string {
  return ms ? new Date(ms).toLocaleString() : "\u2014";
}

/** Client display name: hostname when known, else the MAC. */
export function clientName(hostname: string | undefined, mac: string): string {
  return hostname ? hostname : mac;
}

/** AP display name: the AP's name when known, else its MAC. */
export function apText(name: string | undefined, mac: string | undefined): string {
  return name ? name : (mac ?? "\u2014");
}

/** "2 h 5 m" style span between two unix-ms instants (to=0/undefined => now). */
export function spanText(fromMs: number, toMs?: number): string {
  const end = toMs ? toMs : Date.now();
  let s = Math.max(0, Math.floor((end - fromMs) / 1000));
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d > 0) {
    return d + "d " + h + "h";
  }
  if (h > 0) {
    return h + "h " + m + "m";
  }
  if (m > 0) {
    return m + "m " + s + "s";
  }
  return s + "s";
}

/** Connection text for the clients list: how long the client has been on its AP. */
export function sinceText(sinceSec: number | undefined): string {
  return sinceSec ? spanText(sinceSec * 1000) : "\u2014";
}

export function intervalAp(iv: AssignmentView): string {
  return apText(iv.ap_name, iv.ap);
}

/** The Description column: the server-built message, which already reads
 *  like the official log ("X roamed from ap-a to ap-b."). */
export function eventDescription(ev: EventView): string {
  return ev.msg;
}
