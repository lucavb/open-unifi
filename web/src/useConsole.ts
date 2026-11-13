// The console's single composition root: all section state plus the 5s
// polling loop (whoami → devices → wireless → pending) with the auth gate
// (halted() zero-request guard) and the render gate (rowsHaveEdits + the
// focus check). App calls useConsole() exactly once and provides the store
// down; components read it through useConsoleStore().
import { computed, inject, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import type { InjectionKey } from "vue";
import { api, is401, request, setAuthToken } from "./api";
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

interface WlanEditor {
  rows: WlanRowState[];
  baseline: WlanRowState[];
  latestServer: WlanRowState[];
  hasServer: boolean;
  conflict: boolean;
  loading: boolean;
  saving: boolean;
  error: string;
  loadGeneration: number;
  saveGeneration: number;
}

function cloneWlanRows(rows: WlanRowState[]): WlanRowState[] {
  return rows.map((row) => ({
    ...row,
    acct: row.acct
      ? {
          ...row.acct,
          ...(row.acct.acct_servers !== undefined
            ? { acct_servers: row.acct.acct_servers.map((server) => ({ ...server })) }
            : {})
        }
      : null,
    preserved: { ...row.preserved }
  }));
}

function sameWlanRows(a: WlanRowState[], b: WlanRowState[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function reconcileSubmittedRows(
  currentRows: WlanRowState[],
  submittedRows: WlanRowState[],
  savedRows: WlanRowState[]
): void {
  const savedByClientId = new Map(savedRows.map((row) => [row.clientId, row]));
  for (const submitted of submittedRows) {
    const saved = savedByClientId.get(submitted.clientId);
    const current = currentRows.find((row) => row.clientId === submitted.clientId);
    if (!saved || !current) continue;

    // Reconcile server-owned identity/band/DAS without replacing editable
    // values typed since the request started. A removed row has no live match;
    // a newly added row has no submitted identity and cannot be confused for it.
    current.preserved = { ...saved.preserved };
    if (current.security === submitted.security && saved.security === submitted.security) {
      const savedCopy = cloneWlanRows([saved])[0];
      current.acct = savedCopy.acct;
    }
  }
}

function editorFromEnv(
  env: WlansEnvelope,
  previousRows: WlanRowState[] = [],
  alignToSubmittedOrder = false
): WlanRowState[] {
  const wireRows = env.wlans ?? [];
  if (wireRows.length === 0) {
    const empty = defaultWlanRow();
    if (previousRows.length === 1) empty.clientId = previousRows[0].clientId;
    return [empty];
  }
  return wireRows.map((wireRow, index) => {
    const row = rowFromWlan(wireRow);
    const identityById = wireRow.id === undefined
      ? undefined
      : previousRows.find((previous) => previous.preserved.id === wireRow.id);
    const previousAtIndex = previousRows[index];
    // GET snapshots prefer server identity; for rows that have never had an
    // ID, preserve their prior client key by position. A PUT response is
    // correlated to the exact submitted snapshot's order, then reconciliation
    // back into the live editor uses clientId (never its current index).
    const identityByPosition = alignToSubmittedOrder
      ? previousAtIndex
      : wireRow.id === undefined && previousAtIndex?.preserved.id === undefined
        ? previousAtIndex
        : undefined;
    const identity = identityById ?? identityByPosition;
    if (identity) row.clientId = identity.clientId;
    return row;
  });
}

function emptyEditor(): WlanEditor {
  const rows = [defaultWlanRow()];
  return {
    rows: cloneWlanRows(rows),
    baseline: cloneWlanRows(rows),
    latestServer: cloneWlanRows(rows),
    hasServer: false,
    conflict: false,
    loading: false,
    saving: false,
    error: "",
    loadGeneration: 0,
    saveGeneration: 0
  };
}

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
  const globalWlError = ref("");

  const devices = ref<DeviceRowState[]>([]); // row objects (rowsFrom)
  const knownDeviceMacs = ref<string[]>([]);
  const openClients = ref<Record<string, boolean>>({}); // mac -> expanded
  const clientData = ref<Record<string, ClientView[]>>({}); // mac -> /clients
  const clientLoading = ref<Record<string, boolean>>({});
  const clientRowErrors = ref<Record<string, string>>({});
  const clientGenerations: Record<string, number> = {};
  const pending = ref<PendingView[]>([]); // raw pending candidates
  const addMac = ref("");
  const addName = ref("");

  // Site-wide clients + client event log (opt-in --client-history).
  const clientsError = ref("");
  const siteClients = ref<SiteClientView[]>([]);
  const clientSearch = ref("");
  const selectedClient = ref(""); // MAC whose AP history is open
  const clientHistory = ref<ClientHistoryView | null>(null);
  const clientHistoryError = ref("");
  let clientHistoryGeneration = 0;
  const eventsError = ref("");
  const eventsEnabled = ref<boolean | null>(null); // null until first fetch
  const events = ref<EventView[]>([]);
  let eventsRequestGeneration = 0;
  const evSearch = ref("");
  const evKey = ref("");
  const evRange = ref("1W");

  const wlDevice = ref(""); // select value
  const wlMac = ref(window.sessionStorage.getItem(WL_MAC_KEY) || "");
  // WLAN row state includes secrets, so drafts live only in this page's
  // memory and are never written to sessionStorage/localStorage.
  const wlanEditors = ref<Record<string, WlanEditor>>({});
  const wlanDraftRevision = ref(0);
  const wlans = ref<WlanRowState[]>([]);
  const wlDirty = computed(() => {
    void wlanDraftRevision.value;
    const editor = getCurrentWlanEditor();
    return !!editor && !sameWlanRows(wlans.value, editor.baseline);
  });
  const wlConflict = computed(() => !!getCurrentWlanEditor()?.conflict);
  const wlLoading = computed(() => !!getCurrentWlanEditor()?.loading);
  const wlSaving = computed(() => !!getCurrentWlanEditor()?.saving);
  const wlLoadError = computed(() => !!getCurrentWlanEditor()?.error.startsWith("Wireless settings could not be loaded:"));
  const wlUnavailable = computed(() => !!wlMac.value && !knownDeviceMacs.value.includes(wlMac.value));
  const wlUnavailableDrafts = computed(() => {
    void wlanDraftRevision.value;
    return Object.keys(wlanEditors.value).filter(
      (mac) => !knownDeviceMacs.value.includes(mac) && !devices.value.some((device) => device.mac === mac) &&
        !sameWlanRows(wlanEditors.value[mac].rows, wlanEditors.value[mac].baseline)
    );
  });
  const wlError = computed(() => getCurrentWlanEditor()?.error || globalWlError.value);

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
  function sectionError(e: unknown, prefix: string): string {
    return is401(e) ? "" : prefix + message(e);
  }
  function getCurrentWlanEditor(): WlanEditor | undefined {
    return wlMac.value ? wlanEditors.value[wlMac.value] : undefined;
  }
  function getOrCreateWlanEditor(mac: string): WlanEditor {
    if (!wlanEditors.value[mac]) {
      wlanEditors.value[mac] = emptyEditor();
    }
    // Read back through the reactive ref: returning the assignment expression
    // above would expose the raw object on first creation.
    return wlanEditors.value[mac];
  }
  function setEditorRows(mac: string, editor: WlanEditor, rows: WlanRowState[]): void {
    editor.rows = rows;
    if (wlMac.value === mac) {
      wlans.value = rows;
      // Keep the row array used by v-model and the per-device draft identical.
      editor.rows = wlans.value;
    }
  }
  function activateWlanEditor(mac: string): WlanEditor | undefined {
    if (!mac) {
      wlans.value = [];
      return undefined;
    }
    const editor = getOrCreateWlanEditor(mac);
    wlans.value = editor.rows;
    editor.rows = wlans.value;
    return editor;
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

  async function refreshRound(): Promise<void> {
    // Zero-request guard: parked on the token box with no token saved.
    if (auth.halted()) {
      return;
    }
    try {
      const me = await api<WhoAmI>("/api/v1/whoami");
      globalError.value = "";
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
      } else {
        globalError.value = "";
      }
    }
    if (auth.halted()) {
      return;
    }
    try {
      const env = await api<DevicesEnvelope>("/api/v1/devices");
      const list = env.devices ?? [];
      knownDeviceMacs.value = list.map((device) => device.mac);
      if (forceRender.value || !isEditing()) {
        devices.value = rowsFrom(list);
      }
      updateOpenClients(knownDeviceMacs.value);
      forceRender.value = false;
      syncWlDevice(list);
      devError.value = "";
      await loadDeviceWireless();
    } catch (e) {
      if (!is401(e)) {
        devError.value = "devices: " + message(e);
      } else {
        devError.value = "";
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
      } else {
        pendingError.value = "";
      }
    }
    if (auth.halted()) {
      return;
    }
    await loadClients();
    await loadEvents();
  }

  // A timer tick and user action can arrive while a round is still running.
  // Share one promise and request at most one follow-up round in that case.
  let refreshPromise: Promise<void> | null = null;
  let refreshRequested = false;
  let disposed = false;
  async function refreshAll(): Promise<void> {
    if (refreshPromise) {
      refreshRequested = true;
      return refreshPromise;
    }
    refreshPromise = (async () => {
      do {
        refreshRequested = false;
        await refreshRound();
      } while (refreshRequested && !disposed);
    })();
    try {
      await refreshPromise;
    } finally {
      refreshPromise = null;
    }
  }

  // ---- site-wide clients + client event log -----------------------------------

  async function loadClients(): Promise<void> {
    if (auth.halted()) return;
    try {
      const env = await api<SiteClientsEnvelope>("/api/v1/clients");
      siteClients.value = env.clients ?? [];
      clientsError.value = "";
    } catch (e) {
      if (!is401(e)) {
        clientsError.value = "clients: " + message(e);
      } else {
        clientsError.value = "";
      }
    }
    if (selectedClient.value && !auth.halted()) {
      await loadClientHistory();
    }
  }

  async function loadClientHistory(): Promise<void> {
    const mac = selectedClient.value;
    const generation = ++clientHistoryGeneration;
    if (auth.halted()) return;
    if (!mac) {
      clientHistory.value = null;
      clientHistoryError.value = "";
      return;
    }
    clientHistoryError.value = "";
    try {
      const h = await api<ClientHistoryView>("/api/v1/clients/" + encodeURIComponent(mac) + "/history");
      if (selectedClient.value === mac && generation === clientHistoryGeneration) {
        clientHistory.value = h;
      }
    } catch (e) {
      if (selectedClient.value === mac && generation === clientHistoryGeneration && !is401(e)) {
        clientHistoryError.value = "client history: " + message(e);
      } else if (selectedClient.value === mac && generation === clientHistoryGeneration) {
        clientHistoryError.value = "";
      }
    }
  }

  function selectClient(mac: string): void {
    selectedClient.value = selectedClient.value === mac ? "" : mac;
    clientHistory.value = null;
    clientHistoryError.value = "";
    void loadClientHistory();
  }

  function refreshClientHistory(): void {
    void loadClientHistory();
  }

  async function loadEvents(): Promise<void> {
    if (auth.halted()) return;
    const generation = ++eventsRequestGeneration;
    const range = evRange.value;
    const key = evKey.value;
    const since = Math.floor(Date.now() / 1000) - (EVENT_RANGES[range] ?? EVENT_RANGES["1W"]);
    const q = new URLSearchParams({ since: String(since), limit: String(EVENTS_LIMIT) });
    if (key) {
      q.set("key", key);
    }
    const isCurrent = () => generation === eventsRequestGeneration && key === evKey.value && range === evRange.value;
    try {
      const env = await api<EventsEnvelope>("/api/v1/events?" + q.toString());
      if (!isCurrent()) return;
      eventsEnabled.value = env.enabled;
      events.value = env.events ?? [];
      eventsError.value = "";
    } catch (e) {
      if (!isCurrent()) return;
      if (!is401(e)) {
        eventsError.value = "events: " + message(e);
      } else {
        eventsError.value = "";
      }
    }
  }

  /** Re-query when a server-side filter (event type, range) changes. */
  function onEventFilterChange(ev?: Event): void {
    const target = ev?.target;
    if (target instanceof HTMLSelectElement) {
      if (target.name === "event_key") evKey.value = target.value;
      if (target.name === "event_range") evRange.value = target.value;
    }
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

  async function loadDeviceClients(mac: string, force = false): Promise<void> {
    if (auth.halted() || !openClients.value[mac] || !knownDeviceMacs.value.includes(mac)) {
      return;
    }
    if (clientLoading.value[mac] && !force) {
      return;
    }
    const generation = (clientGenerations[mac] ?? 0) + 1;
    clientGenerations[mac] = generation;
    clientLoading.value[mac] = true;
    clientRowErrors.value[mac] = "";
    try {
      const env = await api<ClientsEnvelope>(devicePath(mac) + "/clients");
      if (
        clientGenerations[mac] === generation &&
        openClients.value[mac] &&
        knownDeviceMacs.value.includes(mac)
      ) {
        clientData.value[mac] = env.clients ?? [];
      }
    } catch (e) {
      if (
        clientGenerations[mac] === generation &&
        openClients.value[mac] &&
        knownDeviceMacs.value.includes(mac) &&
        !is401(e)
      ) {
        clientRowErrors.value[mac] = message(e);
      } else if (clientGenerations[mac] === generation) {
        clientRowErrors.value[mac] = "";
      }
    } finally {
      if (clientGenerations[mac] === generation) {
        clientLoading.value[mac] = false;
      }
    }
  }

  // Prune forgotten devices and refresh only visible expansions. A response
  // from a closed/removed row is invalidated before it can repopulate state.
  function updateOpenClients(macList: string[] = knownDeviceMacs.value): void {
    const present = new Set(macList);
    for (const mac of Object.keys(openClients.value)) {
      if (!present.has(mac)) {
        clientGenerations[mac] = (clientGenerations[mac] ?? 0) + 1;
        delete openClients.value[mac];
        delete clientData.value[mac];
        delete clientLoading.value[mac];
        delete clientRowErrors.value[mac];
      }
    }
    for (const mac of Object.keys(openClients.value)) {
      void loadDeviceClients(mac);
    }
  }

  function refreshDeviceClients(mac: string): void {
    void loadDeviceClients(mac, true);
  }

  // ---- devices: per-row actions ---------------------------------------------

  function toggleClients(row: DeviceRowState): void {
    if (openClients.value[row.mac]) {
      clientGenerations[row.mac] = (clientGenerations[row.mac] ?? 0) + 1;
      delete openClients.value[row.mac];
      delete clientData.value[row.mac];
      delete clientLoading.value[row.mac];
      delete clientRowErrors.value[row.mac];
    } else {
      openClients.value[row.mac] = true;
      void loadDeviceClients(row.mac, true);
    }
  }

  async function forget(row: DeviceRowState): Promise<void> {
    devError.value = "";
    try {
      await request(devicePath(row.mac), { method: "DELETE" });
      await refreshAll();
    } catch (e) {
      devError.value = sectionError(e, "Forget failed: ");
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
      devError.value = sectionError(e, "LED bar save failed: ");
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
      devError.value = sectionError(e, "Country save failed: ");
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
      devError.value = sectionError(e, "SSH keys save failed: ");
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
      devError.value = sectionError(e, "SSH keys clear failed: ");
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
      devError.value = sectionError(e, "SSH password save failed: ");
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
      devError.value = sectionError(e, "Stop managing SSH password failed: ");
    }
  }

  // ---- pending candidates ----------------------------------------------------

  async function adopt(p: PendingView): Promise<void> {
    pendingError.value = "";
    try {
      await request("/api/v1/pending/" + encodeURIComponent(p.mac) + "/adopt", { method: "POST" });
      await refreshAll();
    } catch (e) {
      pendingError.value = sectionError(e, "Adopt failed: ");
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
      addError.value = sectionError(e, "Add failed: ");
    }
  }

  // ---- token -------------------------------------------------------------------

  function saveToken(): void {
    const t = auth.tokenInput.value.replace(/^Bearer\s+/i, "");
    setAuthToken(t);
    // The saved token passes the halted() guard, so this refresh is the
    // immediate full chain; an invalid token re-parks via the 401 path.
    void refreshAll();
  }

  // ---- wireless / VLAN -----------------------------------------------------------

  // Keep a dirty editor selected if its device was removed. Drafts are
  // retained in memory and shown as unavailable until explicitly discarded.
  function syncWlDevice(list: DeviceView[]): void {
    const current = wlMac.value;
    const editor = current ? wlanEditors.value[current] : undefined;
    if (current && list.some((d) => d.mac === current)) {
      wlDevice.value = current;
      return;
    }
    if (current && editor && !sameWlanRows(editor.rows, editor.baseline)) {
      wlDevice.value = current;
      return;
    }
    setWlDevice(list.length > 0 ? list[0].mac : "");
  }

  function setWlDevice(mac: string): void {
    wlMac.value = mac;
    wlDevice.value = mac;
    if (mac) {
      window.sessionStorage.setItem(WL_MAC_KEY, mac);
      activateWlanEditor(mac);
    } else {
      window.sessionStorage.removeItem(WL_MAC_KEY);
      activateWlanEditor("");
    }
  }

  async function loadDeviceWireless(mac = wlMac.value): Promise<void> {
    if (!mac || auth.halted()) {
      return;
    }
    const editor = getOrCreateWlanEditor(mac);
    if (wlMac.value === mac) activateWlanEditor(mac);
    if (editor.saving || !knownDeviceMacs.value.includes(mac)) return;
    const generation = ++editor.loadGeneration;
    editor.loading = true;
    try {
      const env = await api<WlansEnvelope>(deviceWirelessPath(mac));
      if (wlMac.value !== mac || editor.loadGeneration !== generation || editor.saving) return;
      const remoteRows = editorFromEnv(env, editor.baseline);
      editor.latestServer = cloneWlanRows(remoteRows);
      if (!editor.hasServer) {
        const untouched = sameWlanRows(editor.rows, editor.baseline);
        editor.baseline = cloneWlanRows(remoteRows);
        if (untouched) {
          setEditorRows(mac, editor, cloneWlanRows(remoteRows));
        }
        editor.conflict = !sameWlanRows(wlMac.value === mac ? wlans.value : editor.rows, remoteRows);
      } else if (sameWlanRows(wlMac.value === mac ? wlans.value : editor.rows, editor.baseline)) {
        setEditorRows(mac, editor, cloneWlanRows(remoteRows));
        editor.baseline = cloneWlanRows(remoteRows);
        editor.conflict = false;
      } else {
        // Polls never replace an unsaved draft. Surface only a change that
        // differs from the version on which that draft was based.
        editor.conflict = !sameWlanRows(remoteRows, editor.baseline);
      }
      editor.hasServer = true;
      editor.error = "";
    } catch (e) {
      if (wlMac.value === mac && editor.loadGeneration === generation && !is401(e)) {
        editor.error = "Wireless settings could not be loaded: " + message(e);
      } else if (wlMac.value === mac && editor.loadGeneration === generation) {
        editor.error = "";
      }
    } finally {
      if (editor.loadGeneration === generation) editor.loading = false;
    }
  }

  // Reads ev.target.value (NOT wlDevice): the @change listener fires before
  // v-model's own change handler commits the new value, so the select's
  // live DOM value is the source of truth (the old console read the DOM too).
  function onWlDeviceChange(ev: Event): void {
    const el = ev.target;
    if (!(el instanceof HTMLSelectElement)) {
      return;
    }
    if (el.value !== wlMac.value) {
      setWlDevice(el.value);
      void loadDeviceWireless(el.value);
    }
  }

  function addWlanRow(): void {
    wlans.value.push(defaultWlanRow());
    markWlanDraftChanged();
  }

  function removeWlan(i: number): void {
    wlans.value.splice(i, 1);
    markWlanDraftChanged();
  }

  function markWlanDraftChanged(): void {
    wlanDraftRevision.value += 1;
  }

  function discardWlanChanges(): void {
    const editor = getCurrentWlanEditor();
    if (!editor) return;
    const restore = editor.hasServer ? editor.latestServer : editor.baseline;
    setEditorRows(wlMac.value, editor, cloneWlanRows(restore));
    editor.baseline = cloneWlanRows(restore);
    editor.conflict = false;
    editor.error = "";
  }

  function reloadWirelessVersion(): void {
    const editor = getCurrentWlanEditor();
    if (!editor?.hasServer) {
      void loadDeviceWireless();
      return;
    }
    setEditorRows(wlMac.value, editor, cloneWlanRows(editor.latestServer));
    editor.baseline = cloneWlanRows(editor.latestServer);
    editor.conflict = false;
    editor.error = "";
  }

  function retryWirelessLoad(): void {
    void loadDeviceWireless();
  }

  async function saveWlans(overwrite = false): Promise<void> {
    if (auth.halted()) return;
    const mac = wlMac.value;
    const editor = mac ? wlanEditors.value[mac] : undefined;
    if (!mac || !editor) {
      globalWlError.value = "Select a device first.";
      return;
    }
    globalWlError.value = "";
    if (!knownDeviceMacs.value.includes(mac)) {
      editor.error = "This device is no longer managed. Its draft is kept, but it cannot be saved.";
      return;
    }
    if (!editor.hasServer) {
      editor.error = "Wait until the device's wireless settings have loaded before saving.";
      return;
    }
    if (editor.saving) return;
    if (editor.conflict && !overwrite) {
      editor.error = "The server settings changed while you were editing. Review the latest version before saving.";
      return;
    }
    const sentRows = cloneWlanRows(wlans.value);
    const collected = collectWlans(sentRows);
    if ("error" in collected) {
      editor.error = collected.error;
      return;
    }
    const generation = ++editor.saveGeneration;
    ++editor.loadGeneration; // invalidate any GET started before this save
    editor.loading = false;
    editor.saving = true;
    editor.error = "";
    try {
      const saved = await api<WlansEnvelope>(deviceWirelessPath(mac), {
        method: "PUT",
        body: collected
      });
      if (editor.saveGeneration !== generation) return;
      const savedRows = editorFromEnv(saved, sentRows, true);
      editor.latestServer = cloneWlanRows(savedRows);
      editor.baseline = cloneWlanRows(savedRows);
      if (sameWlanRows(editor.rows, sentRows)) {
        setEditorRows(mac, editor, cloneWlanRows(savedRows));
      } else {
        reconcileSubmittedRows(editor.rows, sentRows, savedRows);
      }
      wlanDraftRevision.value += 1;
      // Any typing performed while PUT was pending remains in rows and is
      // now dirty against the returned server snapshot.
      editor.conflict = false;
      editor.hasServer = true;
    } catch (e) {
      if (editor.saveGeneration === generation && !is401(e)) {
        editor.error = "Save failed: " + message(e);
      } else if (editor.saveGeneration === generation) {
        editor.error = "";
      }
    } finally {
      if (editor.saveGeneration === generation) editor.saving = false;
    }
  }

  // ---- lifecycle ------------------------------------------------------------------

  let timer: number | undefined;
  function warnBeforeUnload(event: BeforeUnloadEvent): void {
    const hasDraft = Object.values(wlanEditors.value).some(
      (editor) => editor.saving || !sameWlanRows(editor.rows, editor.baseline)
    );
    if (hasDraft) {
      event.preventDefault();
      event.returnValue = "";
    }
  }
  function schedulePoll(): void {
    if (disposed) return;
    timer = window.setTimeout(() => {
      timer = undefined;
      void refreshAll().finally(schedulePoll);
    }, POLL_MS);
  }
  onMounted(() => {
    window.addEventListener("beforeunload", warnBeforeUnload);
    void refreshAll().finally(schedulePoll);
  });
  onBeforeUnmount(() => {
    disposed = true;
    window.removeEventListener("beforeunload", warnBeforeUnload);
    if (timer !== undefined) {
      window.clearTimeout(timer);
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
    clientLoading,
    clientRowErrors,
    toggleClients,
    refreshDeviceClients,
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
    clientHistoryError,
    selectClient,
    refreshClientHistory,
    clientHistoryId: (mac: string) => "client-history-" + mac.replace(/[^A-Za-z0-9_-]/g, "-"),
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
    wlDirty,
    wlConflict,
    wlLoading,
    wlSaving,
    wlLoadError,
    wlUnavailable,
    wlUnavailableDrafts,
    wlCanSave: computed(() => {
      void wlanDraftRevision.value;
      const editor = getCurrentWlanEditor();
      return !!editor && editor.hasServer && !editor.saving && !editor.conflict &&
        !wlUnavailable.value && !sameWlanRows(wlans.value, editor.baseline);
    }),
    wlCanOverwrite: computed(() => {
      void wlanDraftRevision.value;
      const editor = getCurrentWlanEditor();
      return !!editor && editor.hasServer && editor.conflict && !editor.saving &&
        !wlUnavailable.value && !sameWlanRows(wlans.value, editor.baseline);
    }),
    securitys: SECS,
    radiusModes: RADIUS_MODES,
    onWlDeviceChange,
    addWlanRow,
    removeWlan,
    markWlanDraftChanged,
    saveWlans,
    discardWlanChanges,
    reloadWirelessVersion,
    retryWirelessLoad
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
