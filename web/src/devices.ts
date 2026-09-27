// Device-side pure helpers: the wire view → console row mapping, the state
// badge vocabulary, the last-seen rendering, and the render-gate's value
// half. (The focus half of the gate lives in useConsole — it needs the DOM.)
import type { DeviceRowState, DeviceView } from "./types";

/** The state badge vocabulary: [label, css class] per adminapi state. */
export const STATE_NAMES: { [state: number]: readonly [string, string] | undefined } = {
  1: ["pending", "state-1"],
  2: ["adopting", "state-2"],
  3: ["adopted", "state-3"],
  4: ["lost", "state-4"]
};

/** lastSeenText renders a unix-seconds timestamp as a local time of day
 *  (the console's own clock face); zero/absent means never seen. */
export function lastSeenText(unix?: number): string {
  return unix ? new Date(unix * 1000).toLocaleTimeString() : "\u2014";
}

/** rowsFrom shapes one device record into a per-row editing state. The
 *  SSH password is intentionally not round-tripped into the DOM. */
export function rowsFrom(list: DeviceView[]): DeviceRowState[] {
  return list.map((d) => {
    const info = STATE_NAMES[d.state];
    const cc = d.regulatory_country_code != null ? String(d.regulatory_country_code) : "0";
    const keyLines = Array.isArray(d.ssh_public_keys) ? d.ssh_public_keys.join("\n") : "";
    return {
      mac: d.mac,
      name: d.name || "",
      model: d.model || "",
      ip: d.ip || "",
      adopted: d.state === 3,
      stateLabel: info ? info[0] : "unknown (" + d.state + ")",
      stateClass: info ? info[1] : "state-unknown",
      ledBright: d.led_override_color_brightness != null ? String(d.led_override_color_brightness) : "",
      ledColor: d.led_override_color || "",
      country: cc,
      countrySaved: cc,
      keysText: keyLines,
      keysSaved: keyLines,
      sshPwd: "",
      sshSet: "ssh_password" in d && d.ssh_password !== ""
    };
  });
}

/** The render-gate's value half: an in-progress edit on any adopted row —
 *  a typed SSH password, or a keys/country field that differs from its
 *  saved value. A device refresh must not discard these (5s poll). */
export function rowsHaveEdits(rows: DeviceRowState[]): boolean {
  return rows.some(
    (row) =>
      row.adopted &&
      (row.sshPwd !== "" || row.keysText !== row.keysSaved || row.country !== row.countrySaved)
  );
}
