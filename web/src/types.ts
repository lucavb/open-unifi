// API + UI state types for the admin console.
//
// The wire types mirror the Go JSON shapes in internal/adminapi (adminapi.go
// DeviceView/DevicePatch/DeviceUpsert/PendingView/Wlan/ClientView,
// helpers.go envelope structs) — field names and casing are the wire
// contract; do not rename without updating both sides. The RowState types
// are UI-side only (the console's per-row editing state, not wire shapes).

// ---- wire types -------------------------------------------------------------

/** GET /api/v1/whoami (helpers.go whoAmI). */
export interface WhoAmI {
  server: string;
  version: string;
  authConfigured: boolean;
}

/** One managed device (adminapi.go DeviceView). */
export interface DeviceView {
  mac: string;
  name?: string;
  model?: string;
  firmware?: string;
  ip?: string;
  /** 1 pending, 2 adopting, 3 adopted, 4 lost. */
  state: number;
  last_seen?: number;
  cfg_version?: string;
  applied_cfg?: string;
  in_sync?: boolean;
  wlan_delivery_status?: string;
  wlan_delivery_count?: number;
  wlan_last_attempt?: number;
  vaps_not_running?: string[];
  site_id?: string;
  led_override?: string;
  /** nil on the wire = the jar default 100; an explicit 0 is valid (pointer field). */
  led_override_color_brightness?: number;
  /** "" (omitted) = the jar default #0000ff; stored verbatim. */
  led_override_color?: string;
  /** Present only when a password is managed (echoed for the admin surface). */
  ssh_password?: string;
  /** 0 (omitted) = unset (render default 840). */
  regulatory_country_code?: number;
  ssh_public_keys?: string[];
  pending_command?: string;
  actions?: string[];
}

/** Envelope: GET /api/v1/devices (helpers.go devicesEnvelope). */
export interface DevicesEnvelope {
  devices: DeviceView[];
}

/** PATCH /api/v1/devices/{mac} (adminapi.go DevicePatch): omitted = leave unchanged. */
export interface DevicePatch {
  name?: string;
  site_id?: string;
  led_override?: string;
  led_override_color_brightness?: number;
  led_override_color?: string;
  ssh_password?: string;
  regulatory_country_code?: number;
  ssh_public_keys?: string[];
}

/** POST /api/v1/devices (adminapi.go DeviceUpsert). */
export interface DeviceUpsert {
  mac: string;
  name?: string;
  site_id?: string;
}

/** One pending candidate (adminapi.go PendingView). */
export interface PendingView {
  mac: string;
  source?: string;
  name?: string;
}

/** Envelope: GET /api/v1/pending (helpers.go pendingEnvelope). */
export interface PendingEnvelope {
  pending: PendingView[];
}

/** One client session row (adminapi.go ClientView). */
export interface ClientView {
  mac: string;
  connected: boolean;
  /** unix seconds of the last full inform that proved the client present. */
  last_seen?: number;
}

/** Envelope: GET /api/v1/devices/{mac}/clients (helpers.go clientsEnvelope). */
export interface ClientsEnvelope {
  clients: ClientView[];
}

/** One auth server of a WLAN's inline RADIUS profile (adminapi.go RadiusServer). */
export interface RadiusServer {
  ip: string;
  /** 0/omitted = the system_cfg 1812 default. */
  port?: number;
}

/** One accounting server of the profile (adminapi.go RadiusAcctServer; §12 row 1013). */
export interface RadiusAcctServer {
  ip: string;
  /** 0/omitted = the system_cfg 1813 default. */
  port?: number;
}

/** A WLAN row of the device's wireless config (adminapi.go Wlan). */
export interface Wlan {
  id?: string;
  name?: string;
  ssid: string;
  security: string;
  passphrase?: string;
  vlan: number;
  enabled: boolean;
  band?: string;
  radius_servers?: RadiusServer[];
  radius_secret?: string;
  radius_vlan_mode?: string;
  /** wpa-eap only — the §12 accounting block the console preserves on save. */
  accounting_enabled?: boolean;
  acct_servers?: RadiusAcctServer[];
  interim_update_enabled?: boolean;
  radius_das_enabled?: boolean;
}

/** Envelope: GET/PUT /api/v1/devices/{mac}/wireless (adminapi.go WlansEnvelope). */
export interface WlansEnvelope {
  wlans: Wlan[];
}

// ---- UI-side row state ------------------------------------------------------

/** Per-device console row: the display fields plus the in-progress edit state. */
export interface DeviceRowState {
  mac: string;
  name: string;
  model: string;
  ip: string;
  /** state === 3 — the LED/country/SSH editors render only for adopted devices. */
  adopted: boolean;
  stateLabel: string;
  stateClass: string;
  /** v-model of the brightness number input; "" = leave unchanged (server pointer). */
  ledBright: string;
  /** v-model of the color input; "" = the jar default (explicit clear when saved). */
  ledColor: string;
  /** v-model of the country number input. */
  country: string;
  countrySaved: string;
  /** v-model of the keys textarea (one authorized_keys line per row). */
  keysText: string;
  keysSaved: string;
  /** v-model of the password input; intentionally never populated from the wire. */
  sshPwd: string;
  /** whether the device currently has a managed SSH password. */
  sshSet: boolean;
}

/** The §12 accounting block preserved through console saves (wpa-eap rows only). */
export interface WlanAccounting {
  accounting_enabled: boolean;
  acct_servers: RadiusAcctServer[];
  interim_update_enabled: boolean;
}

/** Per-WLAN console row: editable field state plus the preserved accounting block. */
export interface WlanRowState {
  ssid: string;
  name: string;
  security: string;
  passphrase: string;
  /** v-model of the VLAN number input: the server value (number) until typed (string). */
  vlan: number | string;
  /** compact "ip" / "ip:port" / "[host]:port" text form of radius_servers. */
  radiusServers: string;
  radiusSecret: string;
  radiusVlanMode: string;
  enabled: boolean;
  /** null unless a loaded wpa-eap row carried accounting fields. */
  acct: WlanAccounting | null;
}

/** The wire payload of one WLAN row on save (collectWlans output element). */
export interface WlanRowPayload {
  ssid: string;
  name: string;
  security: string;
  passphrase: string;
  vlan: number;
  enabled: boolean;
  radius_servers?: RadiusServer[];
  radius_secret?: string;
  radius_vlan_mode?: string;
  accounting_enabled?: boolean;
  acct_servers?: RadiusAcctServer[];
  interim_update_enabled?: boolean;
}
