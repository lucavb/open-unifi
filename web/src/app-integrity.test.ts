import { mount, flushPromises } from "@vue/test-utils";
import { defineComponent, h, provide } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ClientsCard from "./components/ClientsCard.vue";
import DevicesCard from "./components/DevicesCard.vue";
import EventsCard from "./components/EventsCard.vue";
import WirelessCard from "./components/WirelessCard.vue";
import { ApiError, api, is401, REQUEST_TIMEOUT_MS, setAuthToken } from "./api";
import { parseVlan, collectWlans, defaultWlanRow, rowFromWlan } from "./wireless";
import { CONSOLE_KEY, useConsole } from "./useConsole";
import type { ConsoleStore } from "./useConsole";
import type { ClientHistoryView, EventView, EventsEnvelope, SiteClientsEnvelope, Wlan, WlansEnvelope } from "./types";

const MAC_A = "AA:AA:AA:AA:AA:01";
const MAC_B = "AA:AA:AA:AA:AA:02";
const CLIENT = "11:22:33:44:55:66";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function wlan(ssid: string): Wlan {
  return { ssid, name: "", security: "open", passphrase: "", vlan: 1, enabled: true };
}

function wlanEnvelope(ssid: string): WlansEnvelope {
  return { wlans: [wlan(ssid)] };
}

function event(key: string, msg: string): EventView {
  return { key, time: 1, datetime: "", client: CLIENT, msg };
}

function eventEnvelope(key: string, msg: string): EventsEnvelope {
  return { enabled: true, events: [event(key, msg)] };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 8; i += 1) await flushPromises();
}

let store: ConsoleStore;
let wrapper: ReturnType<typeof mount> | undefined;
let wirelessGet: (mac: string) => Promise<Response> | Response;
let wirelessPut: (mac: string, body: unknown) => Promise<Response> | Response;
let clientsData: SiteClientsEnvelope;
let fetchMock: ReturnType<typeof vi.fn>;
let devicesList: string[];
let deviceClientsGet: (mac: string) => Promise<Response> | Response;
let historyGet: (mac: string) => Promise<Response> | Response;
let whoamiGet: () => Promise<Response> | Response;
let eventsGet: (key: string) => Promise<Response> | Response;

const Host = defineComponent({
  setup() {
    store = useConsole();
    provide(CONSOLE_KEY, store);
    return () => h("main", [h(DevicesCard), h(ClientsCard), h(EventsCard), h(WirelessCard)]);
  }
});

function pathFor(input: RequestInfo | URL): string {
  return new URL(String(input), "http://console.test").pathname;
}

function wirelessMac(path: string): string {
  const parts = path.split("/");
  return decodeURIComponent(parts[4] ?? "");
}

function makeFetch(): ReturnType<typeof vi.fn> {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = pathFor(input);
    if (path === "/api/v1/whoami") return whoamiGet();
    if (path === "/api/v1/devices") {
      return json({ devices: devicesList.map((mac) => ({ mac, state: 3 })) });
    }
    if (path.endsWith("/wireless")) {
      const mac = wirelessMac(path);
      if (init?.method === "PUT") {
        const body = JSON.parse(String(init.body ?? "{}")) as unknown;
        return wirelessPut(mac, body);
      }
      return wirelessGet(mac);
    }
    if (path === "/api/v1/pending") return json({ pending: [] });
    if (path === "/api/v1/clients") return json(clientsData);
    if (path.startsWith("/api/v1/clients/") && path.endsWith("/history")) {
      const clientMac = decodeURIComponent(path.split("/")[4] ?? "");
      return historyGet(clientMac);
    }
    if (/^\/api\/v1\/devices\/[^/]+\/clients$/.test(path)) {
      const mac = decodeURIComponent(path.split("/")[4] ?? "");
      return deviceClientsGet(mac);
    }
    if (path === "/api/v1/events") {
      const key = new URL(String(input), "http://console.test").searchParams.get("key") ?? "";
      return eventsGet(key);
    }
    return json({ error: "not found" }, 404);
  });
}

async function mountConsole(selectedMac = MAC_A) {
  window.sessionStorage.setItem("ou_wl_mac", selectedMac);
  wrapper = mount(Host, { attachTo: document.body });
  await settle();
  return wrapper;
}

function ssidInput() {
  return wrapper!.get('input[name="ssid"]');
}

describe("frontend integrity behaviors", () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    wirelessGet = (mac) => json(wlanEnvelope(mac === MAC_A ? "Network A" : "Network B"));
    wirelessPut = (_mac, body) => json(body);
    devicesList = [MAC_A, MAC_B];
    deviceClientsGet = () => json({ clients: [] });
    historyGet = (mac) => json({ enabled: true, client: mac, intervals: [] } satisfies ClientHistoryView);
    whoamiGet = () => json({ server: "test", version: "1", authConfigured: false });
    eventsGet = () => json({ enabled: true, events: [] });
    clientsData = {
      clients: [{ mac: CLIENT, hostname: "Laptop", connected: true, ap: MAC_A, ssid: "Office", channel: 36 }]
    };
    fetchMock = makeFetch();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = undefined;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("rejects fractional, malformed, and out-of-range VLAN values without truncating", () => {
    expect(parseVlan("1")).toBe(1);
    expect(parseVlan("4094")).toBe(4094);
    for (const value of ["12.5", "", "0", "4095", "1e2", "-1", "abc"]) {
      expect(parseVlan(value)).toBeNull();
    }
    expect("error" in collectWlans([{ ...defaultWlanRow(), ssid: "test", security: "open", vlan: "12.5" }])).toBe(true);
  });

  it("round-trips server-owned WLAN fields and preserves explicit accounting values", () => {
    const source: Wlan = {
      id: "wlan-id-1",
      band: "5g",
      radius_das_enabled: true,
      ssid: "Office",
      name: "",
      security: "wpa-eap",
      passphrase: "",
      vlan: 7,
      enabled: true,
      radius_servers: [{ ip: "192.0.2.5", port: 1812 }],
      radius_secret: "shared",
      radius_vlan_mode: "optional",
      accounting_enabled: false,
      acct_servers: [],
      interim_update_enabled: false
    };
    const row = rowFromWlan(source);
    const result = collectWlans([row]);
    expect("error" in result).toBe(false);
    if ("error" in result) return;
    expect(result.wlans[0]).toMatchObject({
      id: "wlan-id-1",
      band: "5g",
      radius_das_enabled: true,
      accounting_enabled: false,
      acct_servers: [],
      interim_update_enabled: false
    });

    row.security = "wpa-p";
    row.passphrase = "long-enough-passphrase";
    const changedSecurity = collectWlans([row]);
    expect("error" in changedSecurity).toBe(false);
    if ("error" in changedSecurity) return;
    expect(changedSecurity.wlans[0]).toMatchObject({ id: "wlan-id-1", band: "5g" });
    expect(changedSecurity.wlans[0]).not.toHaveProperty("radius_das_enabled");
    expect(changedSecurity.wlans[0]).not.toHaveProperty("radius_servers");
    expect(changedSecurity.wlans[0]).not.toHaveProperty("radius_secret");
    expect(changedSecurity.wlans[0]).not.toHaveProperty("accounting_enabled");
    expect(changedSecurity.wlans[0]).not.toHaveProperty("acct_servers");
    expect(changedSecurity.wlans[0]).not.toHaveProperty("interim_update_enabled");
  });

  it("detects a conflict when only a preserved server-side WLAN field changes", async () => {
    const original = { ...wlan("Office"), id: "stable-id", band: "5g" };
    let polls = 0;
    wirelessGet = () => json({ wlans: [{ ...original, band: polls++ === 0 ? "5g" : "2g" }] });
    const view = await mountConsole(MAC_A);
    await ssidInput().setValue("Draft SSID");
    await store.refreshAll();
    await settle();
    expect(store.wlConflict).toBe(true);
    expect(view.text()).toContain("The server settings changed while you were editing.");
  });

  it("uses status-bearing auth errors, clears rejected tokens, and invokes the auth gate", async () => {
    window.sessionStorage.setItem("ou_token", "bad-token");
    const unauthorized = vi.fn();
    const previousFetch = window.fetch;
    vi.stubGlobal("fetch", vi.fn(async () => json({ error: "unauthorized" }, 401)));
    const { setUnauthorizedHandler } = await import("./api");
    setUnauthorizedHandler(unauthorized);
    await expect(api("/protected")).rejects.toMatchObject({ status: 401 });
    await expect(api("/protected")).rejects.toBeInstanceOf(ApiError);
    expect(is401(new ApiError("server says 401 in the text", 500))).toBe(false);
    expect(is401(new ApiError("unauthorized", 401))).toBe(true);
    expect(window.sessionStorage.getItem("ou_token")).toBeNull();
    expect(unauthorized).toHaveBeenCalledTimes(2);
    vi.stubGlobal("fetch", previousFetch);
  });

  it("does not let delayed 401s from old requests clear a replacement token", async () => {
    const view = await mountConsole();
    const oldFailureOne = deferred<Response>();
    const oldFailureTwo = deferred<Response>();
    const appFetch = window.fetch;
    const requests = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathFor(input);
      if (path === "/late-one") return oldFailureOne.promise;
      if (path === "/late-two") return oldFailureTwo.promise;
      return appFetch(input, init);
    });
    vi.stubGlobal("fetch", requests);
    setAuthToken("old-token");
    const first = api("/late-one").catch((error: unknown) => error);
    const second = api("/late-two").catch((error: unknown) => error);
    await settle();

    store.tokenInput = "new-token";
    store.saveToken();
    await store.refreshAll();
    await settle();
    expect(window.sessionStorage.getItem("ou_token")).toBe("new-token");
    expect(store.needToken).toBe(false);

    oldFailureOne.resolve(json({ error: "unauthorized" }, 401));
    await first;
    expect(window.sessionStorage.getItem("ou_token")).toBe("new-token");
    expect(store.needToken).toBe(false);
    oldFailureTwo.resolve(json({ error: "unauthorized" }, 401));
    await second;
    expect(window.sessionStorage.getItem("ou_token")).toBe("new-token");
    expect(store.needToken).toBe(false);
    expect(view.text()).not.toContain("401 unauthorized");
  });

  it("coalesces refresh requests into one serialized follow-up poll", async () => {
    const firstWhoami = deferred<Response>();
    let whoamiCalls = 0;
    whoamiGet = () => {
      whoamiCalls += 1;
      return whoamiCalls === 1 ? firstWhoami.promise : json({ server: "test", version: "1", authConfigured: false });
    };
    window.sessionStorage.setItem("ou_wl_mac", MAC_A);
    wrapper = mount(Host);
    await settle();
    const first = store.refreshAll();
    const second = store.refreshAll();
    expect(whoamiCalls).toBe(1);
    firstWhoami.resolve(json({ server: "test", version: "1", authConfigured: false }));
    await Promise.all([first, second]);
    expect(whoamiCalls).toBe(2);
  });

  it("times out a permanently stalled fetch and lets token refresh complete", async () => {
    vi.useFakeTimers();
    const firstWhoami = deferred<Response>();
    let whoamiCalls = 0;
    whoamiGet = () => {
      whoamiCalls += 1;
      return whoamiCalls === 1
        ? firstWhoami.promise
        : json({ server: "test", version: "1", authConfigured: false });
    };

    await mountConsole();
    expect(whoamiCalls).toBe(1);
    store.tokenInput = "replacement-token";
    store.saveToken(); // queues a fresh round behind the stalled shared round

    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    await settle();

    expect(whoamiCalls).toBe(2);
    expect(fetchMock.mock.calls.some(([, init]) =>
      (init?.headers as Record<string, string> | undefined)?.Authorization === "Bearer replacement-token"
    )).toBe(true);
    expect(store.needToken).toBe(false);

    // The normal poll timer is still scheduled after recovery and can run a
    // further round; unmount clears it in the usual lifecycle path.
    await vi.advanceTimersByTimeAsync(5000);
    await settle();
    expect(whoamiCalls).toBeGreaterThan(2);

    firstWhoami.resolve(json({ error: "late unauthorized" }, 401));
    await settle();
    expect(window.sessionStorage.getItem("ou_token")).toBe("replacement-token");
    expect(store.needToken).toBe(false);

    wrapper!.unmount();
    wrapper = undefined;
    expect(vi.getTimerCount()).toBe(0);
  });

  it("bounds response-body parsing as well as fetch", async () => {
    vi.useFakeTimers();
    const pendingFetch = deferred<Response>();
    let fetchSignal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      fetchSignal = init?.signal as AbortSignal | undefined;
      return pendingFetch.promise;
    }));
    setAuthToken("kept-token");
    const stalledFetch = api("/stalled-fetch").catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    const fetchError = await stalledFetch;
    expect(fetchError).toMatchObject({ name: "ApiTimeoutError" });
    expect(is401(fetchError)).toBe(false);
    expect(fetchSignal?.aborted).toBe(true);
    pendingFetch.resolve(json({ error: "late unauthorized" }, 401));
    await settle();
    expect(window.sessionStorage.getItem("ou_token")).toBe("kept-token");

    const pendingBody = deferred<unknown>();
    const response = {
      status: 200,
      ok: true,
      json: () => pendingBody.promise
    } as Response;
    vi.stubGlobal("fetch", vi.fn(async () => response));

    const request = api("/stalled-body").catch((error: unknown) => error);
    await settle();
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);

    const error = await request;
    expect(error).toMatchObject({ name: "ApiTimeoutError" });
    expect(is401(error)).toBe(false);

    vi.stubGlobal("fetch", vi.fn(async () => json({ recovered: true })));
    await expect(api("/recovered")).resolves.toEqual({ recovered: true });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps the selected event filter when responses arrive out of order", async () => {
    const allEvents = deferred<Response>();
    eventsGet = (key) => key === "" ? allEvents.promise : json(eventEnvelope(key, "roam result"));
    const view = await mountConsole();
    await view.get('select[aria-label="Event type"]').setValue("EVT_WU_Roam");
    await settle();
    expect(store.events[0]?.key).toBe("EVT_WU_Roam");
    expect(store.events[0]?.msg).toBe("roam result");

    allEvents.resolve(json(eventEnvelope("EVT_WU_Connected", "stale connect result")));
    await settle();
    expect(store.evKey).toBe("EVT_WU_Roam");
    expect(store.events[0]?.key).toBe("EVT_WU_Roam");
    expect(store.events[0]?.msg).toBe("roam result");
  });

  it("does not let an older event-filter failure replace the current result or error", async () => {
    const staleFailure = deferred<Response>();
    eventsGet = (key) => key === "" ? staleFailure.promise : json(eventEnvelope(key, "current roam result"));
    const view = await mountConsole();
    await view.get('select[aria-label="Event type"]').setValue("EVT_WU_Roam");
    await settle();
    expect(store.eventsError).toBe("");

    staleFailure.reject(new Error("old all-events failure"));
    await settle();
    expect(store.evKey).toBe("EVT_WU_Roam");
    expect(store.events[0]?.msg).toBe("current roam result");
    expect(store.eventsError).toBe("");
  });

  it("ignores a WLAN response for a device that is no longer selected", async () => {
    const oldResponse = deferred<Response>();
    wirelessGet = (mac) => (mac === MAC_A ? oldResponse.promise : json(wlanEnvelope("Network B")));
    const view = await mountConsole(MAC_A);
    expect(fetchMock.mock.calls.some(([input]) => pathFor(input as RequestInfo) === `/api/v1/devices/${encodeURIComponent(MAC_A)}/wireless`)).toBe(true);

    await view.find("#wlDevice").setValue(MAC_B);
    await settle();
    expect((ssidInput().element as HTMLInputElement).value).toBe("Network B");

    oldResponse.resolve(json(wlanEnvelope("Late Network A")));
    await settle();
    expect((ssidInput().element as HTMLInputElement).value).toBe("Network B");
  });

  it("updates the restored WLAN editor reactively on its first successful load", async () => {
    const view = await mountConsole(MAC_A);
    expect(store.wlLoading).toBe(false);
    expect(store.wlLoadError).toBe(false);
    await ssidInput().setValue("First-load edit");
    expect(store.wlCanSave).toBe(true);
    expect(view.text()).not.toContain("Loading wireless settings");
  });

  it("updates the restored WLAN editor reactively on its first failed load", async () => {
    wirelessGet = () => json({ error: "wireless unavailable" }, 503);
    const view = await mountConsole(MAC_A);
    expect(store.wlLoading).toBe(false);
    expect(store.wlLoadError).toBe(true);
    expect(view.text()).toContain("Wireless settings could not be loaded: wireless unavailable");
    expect(view.text()).toContain("Try again");
  });

  it("keeps dirty WLAN drafts through polling and device switches", async () => {
    const view = await mountConsole(MAC_A);
    await ssidInput().setValue("Draft A");
    await store.refreshAll();
    await settle();
    expect(store.wlDirty).toBe(true);
    expect((ssidInput().element as HTMLInputElement).value).toBe("Draft A");

    await view.find("#wlDevice").setValue(MAC_B);
    await settle();
    await view.find("#wlDevice").setValue(MAC_A);
    await settle();
    expect((ssidInput().element as HTMLInputElement).value).toBe("Draft A");
    expect(view.text()).toContain("Unsaved changes. Switching devices keeps this draft.");
    await view.get("#wlDiscard").trigger("click");
    expect(store.wlDirty).toBe(false);
    expect((ssidInput().element as HTMLInputElement).value).toBe("Network A");
  });

  it("keeps a dirty draft selected and unavailable when its device disappears", async () => {
    const view = await mountConsole(MAC_A);
    await ssidInput().setValue("Unmanaged draft");
    devicesList = [MAC_B];
    await store.refreshAll();
    await settle();
    expect(store.wlMac).toBe(MAC_A);
    expect(store.wlUnavailable).toBe(true);
    expect((ssidInput().element as HTMLInputElement).value).toBe("Unmanaged draft");
    expect(view.find("#wlDevice").text()).toContain("no longer managed");
    expect((view.get("#wlSave").element as HTMLButtonElement).disabled).toBe(true);
    await view.find("#wlDevice").setValue(MAC_B);
    await settle();
    await view.find("#wlDevice").setValue(MAC_A);
    await settle();
    expect((ssidInput().element as HTMLInputElement).value).toBe("Unmanaged draft");
  });

  it("requires explicit overwrite after a polled server conflict", async () => {
    const view = await mountConsole(MAC_A);
    await ssidInput().setValue("My draft");
    wirelessGet = () => json(wlanEnvelope("Changed on server"));
    await store.refreshAll();
    await settle();
    expect(store.wlConflict).toBe(true);
    expect(view.text()).toContain("The server settings changed while you were editing.");
    const putsBefore = fetchMock.mock.calls.filter(([, init]) => init?.method === "PUT").length;
    await store.saveWlans();
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === "PUT")).toHaveLength(putsBefore);

    let sent: unknown;
    wirelessPut = (_mac, body) => {
      sent = body;
      return json(body);
    };
    await view.get("#wlSaveAnyway").trigger("click");
    await settle();
    expect(sent).toMatchObject({ wlans: [{ ssid: "My draft" }] });
    expect(store.wlConflict).toBe(false);
    expect(store.wlDirty).toBe(false);
  });

  it("saves to the captured device and preserves edits made while the PUT is pending", async () => {
    const putResponse = deferred<Response>();
    wirelessPut = () => putResponse.promise;
    const view = await mountConsole(MAC_A);
    await ssidInput().setValue("Submitted A");
    const save = store.saveWlans();
    await settle();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true);

    await ssidInput().setValue("Typed while saving");
    expect((ssidInput().element as HTMLInputElement).value).toBe("Typed while saving");
    await view.find("#wlDevice").setValue(MAC_B);
    await settle();
    await ssidInput().setValue("Draft B");
    expect(fetchMock.mock.calls.some(([input, init]) =>
      init?.method === "PUT" && pathFor(input as RequestInfo) === `/api/v1/devices/${encodeURIComponent(MAC_A)}/wireless`
    )).toBe(true);
    putResponse.resolve(json(wlanEnvelope("Submitted A")));
    await save;
    await settle();
    expect((ssidInput().element as HTMLInputElement).value).toBe("Draft B");

    await view.find("#wlDevice").setValue(MAC_A);
    await settle();
    expect((ssidInput().element as HTMLInputElement).value).toBe("Typed while saving");
    expect(store.wlDirty).toBe(true);
  });

  it("reconciles a first-save ID to the submitted row without losing later edits or a new row", async () => {
    wirelessGet = () => json({ wlans: [] });
    const firstPut = deferred<Response>();
    const putBodies: Array<{ wlans: Array<Record<string, unknown>> }> = [];
    wirelessPut = (_mac, body) => {
      const payload = body as { wlans: Array<Record<string, unknown>> };
      putBodies.push(payload);
      if (putBodies.length === 1) return firstPut.promise;
      return json({
        wlans: payload.wlans.map((row, index) => ({ ...row, id: row.id ?? `assigned-${index + 1}` }))
      });
    };
    const view = await mountConsole(MAC_A);
    await view.findAll('input[name="ssid"]')[0].setValue("Submitted SSID");
    await view.findAll('input[name="passphrase"]')[0].setValue("12345678");
    const submittedClientId = store.wlans[0].clientId;
    const firstSave = store.saveWlans();
    await settle();
    expect(putBodies[0].wlans[0]).not.toHaveProperty("id");
    expect(putBodies[0].wlans[0]).not.toHaveProperty("clientId");

    await view.findAll('input[name="ssid"]')[0].setValue("Edited while saving");
    await view.get("#wlAddRow").trigger("click");
    await view.findAll('input[name="ssid"]')[1].setValue("Added while saving");
    await view.findAll('input[name="passphrase"]')[1].setValue("abcdefgh");
    const addedClientId = store.wlans[1].clientId;

    firstPut.resolve(json({
      wlans: [{ ...putBodies[0].wlans[0], id: "assigned-first-id" }]
    }));
    await firstSave;
    await settle();
    expect(store.wlans).toHaveLength(2);
    expect(store.wlans[0].clientId).toBe(submittedClientId);
    expect(store.wlans[0].preserved.id).toBe("assigned-first-id");
    expect(store.wlans[0].ssid).toBe("Edited while saving");
    expect(store.wlans[1].clientId).toBe(addedClientId);
    expect(store.wlans[1].preserved.id).toBeUndefined();

    await store.saveWlans();
    expect(putBodies[1].wlans[0]).toMatchObject({ id: "assigned-first-id", ssid: "Edited while saving" });
    expect(putBodies[1].wlans[1]).toMatchObject({ ssid: "Added while saving" });
    expect(putBodies[1].wlans[1]).not.toHaveProperty("id");
  });

  it("does not attach a saved ID to the wrong row when an earlier submitted row is removed", async () => {
    wirelessGet = () => json({ wlans: [] });
    const firstPut = deferred<Response>();
    const putBodies: Array<{ wlans: Array<Record<string, unknown>> }> = [];
    wirelessPut = (_mac, body) => {
      const payload = body as { wlans: Array<Record<string, unknown>> };
      putBodies.push(payload);
      if (putBodies.length === 1) return firstPut.promise;
      return json({ wlans: payload.wlans });
    };
    const view = await mountConsole(MAC_A);
    await view.get("#wlAddRow").trigger("click");
    await view.findAll('input[name="ssid"]')[0].setValue("First row");
    await view.findAll('input[name="passphrase"]')[0].setValue("12345678");
    await view.findAll('input[name="ssid"]')[1].setValue("Second row");
    await view.findAll('input[name="passphrase"]')[1].setValue("abcdefgh");
    const [firstClientId, secondClientId] = store.wlans.map((row) => row.clientId);
    const firstSave = store.saveWlans();
    await settle();

    await view.findAll('button[aria-label^="Remove WLAN row"]')[0].trigger("click");
    expect(store.wlans).toHaveLength(1);
    expect(store.wlans[0].clientId).toBe(secondClientId);
    firstPut.resolve(json({
      wlans: putBodies[0].wlans.map((row, index) => ({ ...row, id: index === 0 ? "first-id" : "second-id" }))
    }));
    await firstSave;
    await settle();

    expect(store.wlans).toHaveLength(1);
    expect(store.wlans[0].clientId).toBe(secondClientId);
    expect(store.wlans[0].ssid).toBe("Second row");
    expect(store.wlans[0].preserved.id).toBe("second-id");
    await store.saveWlans();
    expect(putBodies[1].wlans).toHaveLength(1);
    expect(putBodies[1].wlans[0]).toMatchObject({ id: "second-id", ssid: "Second row" });
    expect(putBodies[1].wlans[0].id).not.toBe("first-id");
    expect(firstClientId).not.toBe(secondClientId);
  });

  it("warns before navigating away with an in-memory WLAN draft", async () => {
    const view = await mountConsole();
    await ssidInput().setValue("Unsaved secret config");
    const beforeUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(beforeUnload)).toBe(false);
  });

  it("warns before navigation while a save is pending even if the editor matches its old baseline", async () => {
    const pendingPut = deferred<Response>();
    wirelessPut = () => pendingPut.promise;
    const view = await mountConsole();
    await ssidInput().setValue("Submitted");
    const save = store.saveWlans();
    await settle();
    expect(store.wlSaving).toBe(true);

    await ssidInput().setValue("Network A");
    expect(store.wlDirty).toBe(false);
    const beforeUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(beforeUnload)).toBe(false);

    pendingPut.resolve(json(wlanEnvelope("Submitted")));
    await save;
    await settle();
    expect(store.wlDirty).toBe(true);
    expect(view.find("#wlSave").exists()).toBe(true);
  });

  it("keeps a dirty draft when a poll receives 401 and after token re-entry", async () => {
    const view = await mountConsole(MAC_A);
    await ssidInput().setValue("Keep me");
    window.sessionStorage.setItem("ou_token", "old-token");
    wirelessGet = () => json({ error: "unauthorized" }, 401);
    await store.refreshAll();
    await settle();
    expect(window.sessionStorage.getItem("ou_token")).toBeNull();
    expect(store.needToken).toBe(true);
    expect(store.wlDirty).toBe(true);
    expect((ssidInput().element as HTMLInputElement).value).toBe("Keep me");

    window.sessionStorage.setItem("ou_token", "new-token");
    wirelessGet = () => json(wlanEnvelope("Network A"));
    await store.refreshAll();
    await settle();
    expect(store.wlDirty).toBe(true);
    expect((ssidInput().element as HTMLInputElement).value).toBe("Keep me");
    expect(view.find("#wlError").text()).toBe("");
  });

  it("ignores client-session results after an expansion is closed and reopened", async () => {
    const stale = deferred<Response>();
    let requestNumber = 0;
    deviceClientsGet = () => {
      requestNumber += 1;
      return requestNumber === 1 ? stale.promise : json({ clients: [{ mac: "fresh-session", connected: true }] });
    };
    const view = await mountConsole();
    const button = (text: string) => view.findAll("button").find((candidate) => candidate.text() === text)!;
    await button("Clients").trigger("click");
    await settle();
    await button("Hide clients").trigger("click");
    stale.resolve(json({ clients: [{ mac: "stale-session", connected: true }] }));
    await settle();
    await button("Clients").trigger("click");
    await settle();
    expect(view.text()).toContain("fresh-session");
    expect(view.text()).not.toContain("stale-session");
  });

  it("ignores an earlier history response after the same client is reopened", async () => {
    const stale = deferred<Response>();
    let requestNumber = 0;
    historyGet = (mac) => {
      requestNumber += 1;
      if (requestNumber === 1) return stale.promise;
      return json({ enabled: true, client: mac, intervals: [{ ap: "current-ap", from: 1 }] } satisfies ClientHistoryView);
    };
    const view = await mountConsole();
    const toggle = view.get(".client-history-toggle");
    await toggle.trigger("click");
    await settle();
    await toggle.trigger("click");
    await toggle.trigger("click");
    await settle();
    expect(store.clientHistory?.intervals[0]?.ap).toBe("current-ap");
    stale.resolve(json({ enabled: true, client: CLIENT, intervals: [{ ap: "stale-ap", from: 1 }] }));
    await settle();
    expect(store.clientHistory?.intervals[0]?.ap).toBe("current-ap");
  });

  it("uses a focusable native history button and exposes expansion state", async () => {
    const view = await mountConsole();
    const toggle = view.get(".client-history-toggle");
    expect(toggle.element.tagName).toBe("BUTTON");
    expect((toggle.element as HTMLButtonElement).tabIndex).toBe(0);
    expect(toggle.attributes("aria-expanded")).toBe("false");
    (toggle.element as HTMLButtonElement).focus();
    expect(document.activeElement).toBe(toggle.element);

    await toggle.trigger("click");
    await settle();
    expect(toggle.attributes("aria-expanded")).toBe("true");
    expect(document.getElementById(toggle.attributes("aria-controls")!)).not.toBeNull();
    expect(toggle.attributes("aria-label")).toContain("Hide AP history for");
  });

  it("labels WLAN row controls and the remove action for assistive technology", async () => {
    const view = await mountConsole();
    expect(view.get('input[name="ssid"]').attributes("aria-label")).toBe("SSID, row 1");
    expect(view.get('input[name="vlan"]').attributes("step")).toBe("1");
    expect(view.get('button[aria-label^="Remove WLAN row"]').attributes("aria-label")).toContain("row 1");
  });
});
