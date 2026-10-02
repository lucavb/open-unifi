// The console's single composition root: all section state plus the 5s
// polling loop (whoami → devices → wireless → pending) with the auth gate
// (halted() zero-request guard) and the render gate (rowsHaveEdits + the
// focus check). App calls useConsole() exactly once and provides the store
// down; components read it through useConsoleStore().
import { computed, inject, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import type { InjectionKey } from "vue";
import { api, is401, request } from "./api";
import { lastSeenText, rowsFrom, rowsHaveEdits } from "./devices";
import { RADIUS_MODES, SECS, collectWlans, defaultWlanRow, rowFromWlan } from "./wireless";
import { useAuth } from "./useAuth";
import type {
  ClientHistoryView,
  ClientView,
  ClientsEnvelope,
  DevicesEnvelope,
  DevicePatch,
  DeviceRowState,
  DeviceUpsert,
  DeviceView,
  EventView,
  EventsEnvelope,
  PendingEnvelope,
  PendingView,
  SiteClientView,
  SiteClientsEnvelope,
  WhoAmI,
  WlansEnvelope,
  WlanRowState
} from "./types";

const POLL_MS = 5000;
const WL_MAC_KEY = "ou_wl_mac";
const EVENTS_LIMIT = 1000;

/** Time ranges of the event log filter (the official System Log's 1D/3D/1W/1M). */
export const EVENT_RANGES: Record<string, number> = {
  "1D": 86400,
  "3D": 3 * 86400,
  "1W": 7 * 86400,
  "1M": 30 * 86400
};

export function useConsole() {
  const auth = useAuth();

  // ---- section state -------------------------------------------------------
  const globalError = ref("");
  const devError = ref("");
  const pendingError = ref("");
  const addError = ref("");
  const wlError = ref("");

  const devices = ref<DeviceRowState[]>([]); // row objects (rowsFrom)
  const openClients = ref<Record<string, boolean>>({}); // mac -> expanded
  const clientData = ref<Record<string, ClientView[]>>({}); // mac -> /clients
  const pending = ref<PendingView[]>([]); // raw pending candidates
  const addMac = ref("");
  const addName = ref("");

  // Site-wide clients + client event log (opt-in --client-history).
  const clientsError = ref("");
  const siteClients = ref<SiteClientView[]>([]);
  const clientSearch = ref("");
  const selectedClient = ref(""); // MAC whose AP history is open
  const clientHistory = ref<ClientHistoryView | null>(null);
  const eventsError = ref("");
  const eventsEnabled = ref<boolean | null>(null); // null until first fetch
  const events = ref<EventView[]>([]);
  const evSearch = ref("");
  const evKey = ref("");
  const evRange = ref("1W");

  const wlDevice = ref(""); // select value
  const wlMac = ref(window.sessionStorage.getItem(WL_MAC_KEY) || "");
  const wlans = ref<WlanRowState[]>([]); // row objects (rowFromWlan)

  // A device refresh must not discard an in-progress password entry: this
  // is only a render gate, set by the explicit save actions so their
  // refresh replaces the row after the request completes.
  const forceRender = ref(false);

  // ---- helpers --------------------------------------------------------------
  function devicePath(mac: string): string {
    return "/api/v1/devices/" + encodeURIComponent(mac);
  }
  function deviceWirelessPath(mac: string): string {
    return devicePath(mac) + "/wireless";
  }
  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // ---- polling: whoami → devices → wireless → pending, auth-gated ----------

  // Render gate: a poll must not replace the row state while an edit is in
  // progress — either a field value differs from its saved snapshot, or one
  // of the three named inputs holds focus. activeElement is document-global,
  // so this still works now that the inputs live in child components.
  function isEditing(): boolean {
    if (rowsHaveEdits(devices.value)) {
      return true;
    }
    const a = document.activeElement;
    if (!(a instanceof HTMLInputElement || a instanceof HTMLSelectElement || a instanceof HTMLTextAreaElement)) {
      return false;
    }
    return (
      a.closest("#devTable") !== null &&
      (a.name === "ssh_password" || a.name === "ssh_public_keys" || a.name === "regulatory_country_code")
    );
  }

  async function refreshAll(): Promise<void> {
    // Zero-request guard: parked on the token box with no token saved.
    if (auth.halted()) {
      return;
    }
    try {
      const me = await api<WhoAmI>("/api/v1/whoami");
      auth.whoami.value =
        "server: " + me.server + " " + me.version +
        (me.authConfigured ? " \u00b7 auth enabled" : " \u00b7 no auth");
      // The probe settles the auth state: auth configured without a token
      // parks the console (the data chain would just 401); no-auth servers
      // and a present token clear the park.
      if (me.authConfigured && !window.sessionStorage.getItem("ou_token")) {
        auth.needToken.value = true;
        auth.showToken("");
      } else {
        auth.needToken.value = false;
      }
    } catch (e) {
      // 401s are surfaced by the auth flow (showToken) only — they are not
      // data errors, so no section shows a red pill for them. api() has
      // already cleared the token and parked the console, so the guard
      // below halts this round instead of firing 401-after-401.
      if (!is401(e)) {
        globalError.value = message(e);
      }
    }
    if (auth.halted()) {
      return;
    }
    try {
      const env = await api<DevicesEnvelope>("/api/v1/devices");
      const list = env.devices ?? [];
      if (forceRender.value || !isEditing()) {
        devices.value = rowsFrom(list);
        updateOpenClients();
      }
      forceRender.value = false;
      syncWlDevice(list);
      devError.value = "";
      try {
        await loadDeviceWireless();
      } catch (e) {
        if (!is401(e)) {
          wlError.value = "wireless: " + message(e);
        }
      }
    } catch (e) {
      if (!is401(e)) {
        devError.value = "devices: " + message(e);
      }
    }
    if (auth.halted()) {
      return;
    }
    try {
      const env = await api<PendingEnvelope>("/api/v1/pending");
      pending.value = env.pending ?? [];
      pendingError.value = "";
    } catch (e) {
      if (!is401(e)) {
        pendingError.value = "pending: " + message(e);
      }
    }
    if (auth.halted()) {
      return;
    }
    await loadClients();
    await loadEvents();
  }

  // ---- site-wide clients + client event log -----------------------------------

  async function loadClients(): Promise<void> {
    try {
      const env = await api<SiteClientsEnvelope>("/api/v1/clients");
      siteClients.value = env.clients ?? [];
      clientsError.value = "";
    } catch (e) {
      if (!is401(e)) {
        clientsError.value = "clients: " + message(e);
      }
    }
    if (selectedClient.value) {
      await loadClientHistory();
    }
  }

  async function loadClientHistory(): Promise<void> {
    const mac = selectedClient.value;
    if (!mac) {
      clientHistory.value = null;
      return;
    }
    try {
      const h = await api<ClientHistoryView>("/api/v1/clients/" + encodeURIComponent(mac) + "/history");
      if (selectedClient.value === mac) {
        clientHistory.value = h;
      }
    } catch (e) {
      if (!is401(e)) {
        clientsError.value = "client history: " + message(e);
      }
    }
  }

  function selectClient(mac: string): void {
    selectedClient.value = selectedClient.value === mac ? "" : mac;
    clientHistory.value = null;
    void loadClientHistory();
  }

  async function loadEvents(): Promise<void> {
    const since = Math.floor(Date.now() / 1000) - (EVENT_RANGES[evRange.value] ?? EVENT_RANGES["1W"]);
    const q = new URLSearchParams({ since: String(since), limit: String(EVENTS_LIMIT) });
    if (evKey.value) {
      q.set("key", evKey.value);
    }
    try {
      const env = await api<EventsEnvelope>("/api/v1/events?" + q.toString());
      eventsEnabled.value = env.enabled;
      events.value = env.events ?? [];
      eventsError.value = "";
    } catch (e) {
      if (!is401(e)) {
        eventsError.value = "events: " + message(e);
      }
    }
  }

  /** Re-query when a server-side filter (event type, range) changes. */
  function onEventFilterChange(): void {
    void loadEvents();
  }

  const filteredClients = computed(() => {
    const needle = clientSearch.value.trim().toLowerCase();
    if (!needle) {
      return siteClients.value;
    }
    return siteClients.value.filter((cl) =>
      [cl.mac, cl.hostname, cl.ap, cl.ap_name, cl.ssid].some((v) => (v ?? "").toLowerCase().includes(needle))
    );
  });

  const filteredEvents = computed(() => {
    const needle = evSearch.value.trim().toLowerCase();
    if (!needle) {
      return events.value;
    }
    return events.value.filter((ev) =>
      [ev.client, ev.hostname, ev.ap, ev.ap_name, ev.ap_from, ev.ap_from_name, ev.ap_to, ev.ap_to_name, ev.ssid, ev.msg].some(
        (v) => (v ?? "").toLowerCase().includes(needle)
      )
    );
  });

  // updateOpenClients refreshes the expansion rows: every open device
  // fetches its client sessions (lazily, on demand). A failed fetch (e.g.
  // the device was forgotten) closes the row and surfaces the error once
  // instead of failing on every poll. (No 401 suppression here, as in the
  // old console: a 401 parks via api() AND shows the clients pill.)
  function updateOpenClients(): void {
    for (const mac of Object.keys(openClients.value)) {
      api<ClientsEnvelope>(devicePath(mac) + "/clients")
        .then((env) => {
          clientData.value[mac] = env.clients ?? [];
        })
        .catch((e: unknown) => {
          delete openClients.value[mac];
          devError.value = "clients: " + message(e);
        });
    }
  }

  // ---- devices: per-row actions ---------------------------------------------

  function toggleClients(row: DeviceRowState): void {
    if (openClients.value[row.mac]) {
      delete openClients.value[row.mac];
    } else {
      openClients.value[row.mac] = true;
    }
    updateOpenClients();
  }

  async function forget(row: DeviceRowState): Promise<void> {
    devError.value = "";
    try {
      await request(devicePath(row.mac), { method: "DELETE" });
      await refreshAll();
    } catch (e) {
      devError.value = "forget failed: " + message(e);
    }
  }

  async function saveLed(row: DeviceRowState): Promise<void> {
    devError.value = "";
    const bright = String(row.ledBright).trim();
    const color = String(row.ledColor).trim();
    // Brightness: only an explicit non-empty 0..100 number is sent — an
    // empty input means "leave unchanged" (the server's pointer semantics).
    // Color is always sent (trimmed); the input round-trips the stored
    // value, so this is a no-op unless edited.
    const body: DevicePatch = { led_override_color: color };
    if (bright !== "") {
      if (!/^\d+$/.test(bright) || Number(bright) > 100) {
        devError.value = "LED brightness must be 0..100";
        return;
      }
      body.led_override_color_brightness = Number(bright);
    }
    try {
      await request(devicePath(row.mac), { method: "PATCH", body });
      await refreshAll();
    } catch (e) {
      devError.value = "LED bar save failed: " + message(e);
    }
  }

  async function saveCountry(row: DeviceRowState): Promise<void> {
    devError.value = "";
    const raw = String(row.country).trim();
    const code = raw === "" ? 0 : Number(raw);
    if (!/^\d+$/.test(raw === "" ? "0" : raw) || code < 0 || code > 999) {
      devError.value = "Regulatory country must be 0..999";
      return;
    }
    try {
      await request(devicePath(row.mac), { method: "PATCH", body: { regulatory_country_code: code } });
      forceRender.value = true;
      await refreshAll();
    } catch (e) {
      devError.value = "country save failed: " + message(e);
    }
  }

  async function saveKeys(row: DeviceRowState): Promise<void> {
    devError.value = "";
    const lines = String(row.keysText)
      .split(/\n/)
      .map((s) => s.trim())
      .filter((s) => s !== "");
    try {
      await request(devicePath(row.mac), { method: "PATCH", body: { ssh_public_keys: lines } });
      forceRender.value = true;
      await refreshAll();
    } catch (e) {
      devError.value = "SSH keys save failed: " + message(e);
    }
  }

  async function clearKeys(row: DeviceRowState): Promise<void> {
    if (!window.confirm("Clear managed SSH public keys for this device?")) {
      return;
    }
    devError.value = "";
    try {
      await request(devicePath(row.mac), { method: "PATCH", body: { ssh_public_keys: [] } });
      forceRender.value = true;
      await refreshAll();
    } catch (e) {
      devError.value = "SSH keys clear failed: " + message(e);
    }
  }

  async function saveSsh(row: DeviceRowState): Promise<void> {
    devError.value = "";
    const password = String(row.sshPwd);
    const body: DevicePatch = {};
    // An empty input is deliberately omitted: it means "leave unchanged",
    // never "stop managing".
    if (password !== "") {
      body.ssh_password = password;
    }
    try {
      await request(devicePath(row.mac), { method: "PATCH", body });
      forceRender.value = true;
      await refreshAll();
    } catch (e) {
      devError.value = "SSH password save failed: " + message(e);
    }
  }

  async function clearSsh(row: DeviceRowState): Promise<void> {
    if (!window.confirm("Stop managing this device's SSH password? The device will keep its current password.")) {
      return;
    }
    devError.value = "";
    try {
      await request(devicePath(row.mac), { method: "PATCH", body: { ssh_password: "" } });
      forceRender.value = true;
      await refreshAll();
    } catch (e) {
      devError.value = "stop managing SSH password failed: " + message(e);
    }
  }

  // ---- pending candidates ----------------------------------------------------

  async function adopt(p: PendingView): Promise<void> {
    pendingError.value = "";
    try {
      await request("/api/v1/pending/" + encodeURIComponent(p.mac) + "/adopt", { method: "POST" });
      await refreshAll();
    } catch (e) {
      pendingError.value = "adopt failed: " + message(e);
    }
  }

  // ---- add manually ------------------------------------------------------------

  async function addDevice(): Promise<void> {
    addError.value = "";
    try {
      const body: DeviceUpsert = { mac: addMac.value, name: addName.value };
      await request("/api/v1/devices", { method: "POST", body });
      addMac.value = "";
      addName.value = "";
      await refreshAll();
    } catch (e) {
      addError.value = "add failed: " + message(e);
    }
  }

  // ---- token -------------------------------------------------------------------

  function saveToken(): void {
    const t = auth.tokenInput.value.replace(/^Bearer\s+/i, "");
    window.sessionStorage.setItem("ou_token", t);
    // The saved token passes the halted() guard, so this refresh is the
    // immediate full chain; an invalid token re-parks via the 401 path.
    void refreshAll();
  }

  // ---- wireless / VLAN -----------------------------------------------------------

  // syncWlDevice keeps the selector on a device that still exists (falling
  // back to the first) and persists the pick in sessionStorage.
  function syncWlDevice(list: DeviceView[]): void {
    let pick = wlMac.value || wlDevice.value;
    if (!pick || !list.some((d) => d.mac === pick)) {
      pick = list.length > 0 ? list[0].mac : "";
    }
    wlMac.value = pick;
    wlDevice.value = pick;
    if (pick) {
      window.sessionStorage.setItem(WL_MAC_KEY, pick);
    } else {
      window.sessionStorage.removeItem(WL_MAC_KEY);
    }
  }

  function applyWirelessEnv(env: WlansEnvelope): void {
    let rows = (env.wlans ?? []).map(rowFromWlan);
    if (rows.length === 0) {
      rows = [defaultWlanRow()];
    }
    wlans.value = rows;
  }

  async function loadDeviceWireless(): Promise<void> {
    if (!wlMac.value) {
      applyWirelessEnv({ wlans: [] });
      wlError.value = "";
      return;
    }
    const env = await api<WlansEnvelope>(deviceWirelessPath(wlMac.value));
    applyWirelessEnv(env);
    wlError.value = "";
  }

  // Reads ev.target.value (NOT wlDevice): the @change listener fires before
  // v-model's own change handler commits the new value, so the select's
  // live DOM value is the source of truth (the old console read the DOM too).
  function onWlDeviceChange(ev: Event): void {
    const el = ev.target;
    if (!(el instanceof HTMLSelectElement)) {
      return;
    }
    wlMac.value = el.value;
    if (wlMac.value) {
      window.sessionStorage.setItem(WL_MAC_KEY, wlMac.value);
    } else {
      window.sessionStorage.removeItem(WL_MAC_KEY);
    }
    void loadDeviceWireless().catch((e: unknown) => {
      if (!is401(e)) {
        wlError.value = "wireless: " + message(e);
      }
    });
  }

  function addWlanRow(): void {
    wlans.value.push(defaultWlanRow());
  }

  function removeWlan(i: number): void {
    wlans.value.splice(i, 1);
  }

  async function saveWlans(): Promise<void> {
    wlError.value = "";
    if (!wlMac.value) {
      wlError.value = "select a device first";
      return;
    }
    const collected = collectWlans(wlans.value);
    if ("error" in collected) {
      wlError.value = collected.error;
      return;
    }
    try {
      const saved = await api<WlansEnvelope>(deviceWirelessPath(wlMac.value), {
        method: "PUT",
        body: collected
      });
      applyWirelessEnv(saved);
    } catch (e) {
      wlError.value = "save failed: " + message(e);
    }
  }

  // ---- lifecycle ------------------------------------------------------------------

  let timer: number | undefined;
  onMounted(() => {
    void refreshAll();
    timer = window.setInterval(() => {
      void refreshAll();
    }, POLL_MS);
  });
  onBeforeUnmount(() => {
    if (timer !== undefined) {
      window.clearInterval(timer);
    }
  });

  // ---- the store (App provides it; templates see unwrapped ref values) ----------
  return reactive({
    whoami: auth.whoami,
    showTokenBox: auth.showTokenBox,
    tokenInput: auth.tokenInput,
    needToken: auth.needToken,
    registerTokenFocus: auth.registerTokenFocus,
    saveToken,
    refreshAll,
    globalError,
    devError,
    pendingError,
    addError,
    wlError,
    devices,
    openClients,
    clientData,
    toggleClients,
    forget,
    saveLed,
    saveCountry,
    saveKeys,
    clearKeys,
    saveSsh,
    clearSsh,
    lastSeenText,
    clientsError,
    siteClients,
    clientSearch,
    filteredClients,
    selectedClient,
    clientHistory,
    selectClient,
    eventsError,
    eventsEnabled,
    events,
    filteredEvents,
    evSearch,
    evKey,
    evRange,
    eventRanges: Object.keys(EVENT_RANGES),
    onEventFilterChange,
    pending,
    adopt,
    addMac,
    addName,
    addDevice,
    wlDevice,
    wlMac,
    wlans,
    securitys: SECS,
    radiusModes: RADIUS_MODES,
    onWlDeviceChange,
    addWlanRow,
    removeWlan,
    saveWlans
  });
}

/** The store's type (reactive wrapper unwrapped for the injection key). */
export type ConsoleStore = ReturnType<typeof useConsole>;

export const CONSOLE_KEY: InjectionKey<ConsoleStore> = Symbol("open-unifi console store");

/** Component-side accessor: inject the store App provides. Throws rather
 *  than returning a nullable — a console component outside the root is a
 *  wiring bug, not a runtime state. */
export function useConsoleStore(): ConsoleStore {
  const store = inject(CONSOLE_KEY, null);
  if (store === null) {
    throw new Error("console component used outside the App root that provides CONSOLE_KEY");
  }
  return store;
}
