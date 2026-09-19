package server

// Client-session end-to-end on the ENCRYPTED lane (the §6.2(e) decision
// lives in the connected-equality branch, which the plaintext lane never
// reaches — decidePlain has no cfgversion-match noop): sealed informs
// with station tables record session rows, survive sparse heartbeats
// (device-refreshable caps semantics), fire the Config.OnSessionEvents
// hook, and a disconnect event against a blocked set answers the very
// inform that observed the absence with the §6.2(e) blocked_sta
// reconnect push (docs/PROTOCOL-mgmt.md §6.2 catalog row (e)).

import (
	"net/http"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// sessionEvents captures Config.OnSessionEvents calls: (device mac,
// connects, disconnects) tuples in fire order.
type sessionEvents struct {
	calls []eventCall
}

type eventCall struct {
	mac         string
	connects    int
	disconnects int
}

func (se *sessionEvents) hook() func(string, int, int) {
	return func(mac string, connects, disconnects int) {
		se.calls = append(se.calls, eventCall{mac, connects, disconnects})
	}
}

// seInform posts one sealed CBC inform under the device's assigned key,
// echoing cfg and optionally carrying a station table and/or a
// vap_table. nil staTable = absent (a sparse heartbeat). Returns the
// decrypted reply map.
func seInform(t *testing.T, h http.Handler, xkey, cfg string, staTable, vapTable []any) map[string]any {
	t.Helper()
	body := infoBody(cfg)
	if staTable != nil {
		body["sta_table"] = staTable
	}
	if vapTable != nil {
		body["vap_table"] = vapTable
	}
	resp := post(t, h, encryptCBC(t, mustJSON(t, body), hexKey(t, xkey), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform status = %d %q", resp.Code, resp.Body.String())
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	return jm
}

// staRows builds a station table from client MACs.
func staRows(macs ...string) []any {
	rows := make([]any, 0, len(macs))
	for _, m := range macs {
		rows = append(rows, map[string]any{"mac": m})
	}
	return rows
}

// settleFromAdopted drives a registerAdopted device to the settled
// connected state on the encrypted lane: the equality self-heal mint
// (no envelope baseline yet), the forced full provisioning that captures
// the pending envelope, and the applied echo + empty vap_table that
// confirms settle (the driveToSettled sequence, at the transport).
// staTable is the station table each inform carries (nil = absent).
// Returns the post-settle cfgversion every later connected echo uses.
func settleFromAdopted(t *testing.T, h http.Handler, st store.DeviceStore, xkey string, staTable []any) string {
	t.Helper()
	// Self-heal mint: the first equality inform (no wlan_cfg_sha) answers
	// a noop and mints a fresh cfgversion.
	if jm := seInform(t, h, xkey, "aaaa", staTable, nil); jm["_type"] != "noop" {
		t.Fatalf("self-heal inform = %v, want noop (fresh mint)", jm["_type"])
	}
	// The stale echo mismatches the mint → full provisioning (captures the
	// pending envelope, stamps the blocked baseline).
	if jm := seInform(t, h, xkey, "aaaa", staTable, nil); jm["_type"] != "setparam" {
		t.Fatalf("provisioning inform = %v, want setparam full provisioning", jm["_type"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	cfg := rec.CfgVersion
	// Applied echo + vap_table proving the empty envelope → settle
	// confirms, the connected noop returns, the record is adopted.
	if jm := seInform(t, h, xkey, cfg, staTable, []any{}); jm["_type"] != "noop" {
		t.Fatalf("settle inform = %v, want noop", jm["_type"])
	}
	if rec, err = st.Get(testMAC); err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopted || rec.Extra["wlan_cfg_sha"] == nil {
		t.Fatalf("settle did not confirm: state=%d sha=%v", rec.State, rec.Extra["wlan_cfg_sha"])
	}
	return cfg
}

// TestClientSessionsAcrossInforms walks the session lifecycle at the
// transport boundary: two stations record as connected rows (connect
// events on the hook), a sparse heartbeat wipes nothing, a station going
// absent flips its row to disconnected (disconnect event), and — with NO
// blocked clients — the reply stays the connected noop (the (e) trigger
// is consumed with nothing to push), and a later return is a connect
// event again.
func TestClientSessionsAcrossInforms(t *testing.T) {
	se := &sessionEvents{}
	h, st := newServerWith(Config{OnSessionEvents: se.hook()})
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", xkey)

	const clientA = "00:11:22:33:44:55"
	const clientB = "11:22:33:44:55:66"
	both := staRows(clientA, clientB)

	cfg := settleFromAdopted(t, h, st, xkey, both)

	// Settled with both stations: rows connected, both connect events on
	// the hook (one per inform that first saw each station: the mint,
	// provisioning and settle informs each carried the table; only the
	// FIRST sighting counts).
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	rows := store.ClientSessions(rec)
	if len(rows) != 2 ||
		rows[0].MAC != "001122334455" || !rows[0].Connected || rows[0].LastSeen == 0 ||
		rows[1].MAC != "112233445566" || !rows[1].Connected {
		t.Fatalf("rows after settle = %+v, want both connected", rows)
	}
	if len(se.calls) != 1 || se.calls[0].mac != "aa:bb:cc:dd:ee:ff" ||
		se.calls[0].connects != 2 || se.calls[0].disconnects != 0 {
		t.Fatalf("hook calls = %+v, want one (2 connects)", se.calls)
	}

	// Sparse heartbeat (no station table): rows survive untouched, the
	// hook stays silent.
	if jm := seInform(t, h, xkey, cfg, nil, nil); jm["_type"] != "noop" {
		t.Fatalf("sparse heartbeat = %v, want noop", jm["_type"])
	}
	if rec, err = st.Get(testMAC); err != nil {
		t.Fatal(err)
	}
	if rows = store.ClientSessions(rec); len(rows) != 2 || !rows[0].Connected || !rows[1].Connected {
		t.Fatalf("sparse heartbeat wiped rows: %+v", rows)
	}
	if len(se.calls) != 1 {
		t.Fatalf("hook fired on a sparse heartbeat: %+v", se.calls)
	}

	// Next full inform carries only clientA: clientB disconnected. With no
	// blocked clients the reply stays the connected noop and the event is
	// consumed.
	if jm := seInform(t, h, xkey, cfg, staRows(clientA), nil); jm["_type"] != "noop" {
		t.Fatalf("disconnect with no blocked set: reply = %v, want noop", jm["_type"])
	}
	if rec, err = st.Get(testMAC); err != nil {
		t.Fatal(err)
	}
	if rows = store.ClientSessions(rec); len(rows) != 2 || !rows[0].Connected || rows[1].Connected {
		t.Fatalf("rows after disconnect = %+v, want clientA connected, clientB not", rows)
	}
	if rec.Extra[store.SessionDisconnectEventExtraKey] != nil {
		t.Fatalf("disconnect event survived the connected noop: %v", rec.Extra[store.SessionDisconnectEventExtraKey])
	}
	if len(se.calls) != 2 || se.calls[1].connects != 0 || se.calls[1].disconnects != 1 {
		t.Fatalf("hook calls = %+v, want the disconnect counted", se.calls)
	}

	// ClientB returns: a reconnect is a connect event again.
	if jm := seInform(t, h, xkey, cfg, both, nil); jm["_type"] != "noop" {
		t.Fatalf("reconnect inform = %v, want noop", jm["_type"])
	}
	if rec, err = st.Get(testMAC); err != nil {
		t.Fatal(err)
	}
	if rows = store.ClientSessions(rec); len(rows) != 2 || !rows[1].Connected {
		t.Fatalf("rows after reconnect = %+v, want clientB connected again", rows)
	}
	if len(se.calls) != 3 || se.calls[2].connects != 1 || se.calls[2].disconnects != 0 {
		t.Fatalf("hook calls = %+v, want the reconnect counted as a connect", se.calls)
	}
}

// TestDisconnectEventDeliversReconnectPushOnTheWire: a disconnect event on
// an adopted device with blocked clients answers the very inform that
// observed the absence with the §6.2(e) push — a setparam carrying
// blocked_sta ONLY — and the event never fires twice.
func TestDisconnectEventDeliversReconnectPushOnTheWire(t *testing.T) {
	se := &sessionEvents{}
	h, st := newServerWith(Config{OnSessionEvents: se.hook()})
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", xkey)
	const blocked = "00:11:22:33:44:55"
	if err := st.Update(testMAC, func(d *store.Device) error {
		_, err := store.AddBlockedClient(d, blocked)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Inform #1 (the blocked client IS associated): the absent blocked
	// baseline + non-empty set is blocked drift (§6.2(d)) — a fresh mint
	// and full provisioning carrying the wire set, which also stamps the
	// delivery baseline. The station table records the client connected.
	jm := seInform(t, h, xkey, "aaaa", staRows(blocked), nil)
	if jm["_type"] != "setparam" || jm["blocked_sta"] != blocked {
		t.Fatalf("inform #1 = %v, want the (d) full provisioning carrying blocked_sta", jm["_type"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Extra["blocked_sta_sha"] == nil {
		t.Fatalf("(d) delivery did not stamp the blocked baseline: %+v", rec.Extra)
	}
	cfg := rec.CfgVersion

	// Inform #2: applied echo + vap_table proving the empty envelope →
	// settle confirms, the connected noop returns, the record is adopted.
	if jm = seInform(t, h, xkey, cfg, staRows(blocked), []any{}); jm["_type"] != "noop" {
		t.Fatalf("settle inform = %v, want noop", jm["_type"])
	}
	if rec, err = st.Get(testMAC); err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopted || rec.Extra["wlan_cfg_sha"] == nil {
		t.Fatalf("settle did not confirm: state=%d sha=%v", rec.State, rec.Extra["wlan_cfg_sha"])
	}

	// Settled with the client associated: connected noop, no event.
	if jm = seInform(t, h, xkey, cfg, staRows(blocked), nil); jm["_type"] != "noop" {
		t.Fatalf("connected inform = %v, want noop", jm["_type"])
	}

	// The client is gone (an empty station table — the device reports
	// zero clients). The §6.2(e) push rides THIS reply: the exact
	// three-key setparam, blocked_sta only, NO cfgversion mint.
	jm = seInform(t, h, xkey, cfg, []any{}, nil)
	if jm["_type"] != "setparam" {
		t.Fatalf("disconnect reply type = %v, want the (e) setparam", jm["_type"])
	}
	exactKeys(t, jm, "_type", "blocked_sta", "server_time_in_utc")
	if jm["blocked_sta"] != blocked {
		t.Fatalf("(e) reply blocked_sta = %v, want %q", jm["blocked_sta"], blocked)
	}
	if rec, err = st.Get(testMAC); err != nil {
		t.Fatal(err)
	}
	if rec.Extra[store.SessionDisconnectEventExtraKey] != nil {
		t.Fatalf("event survived the (e) push: %v", rec.Extra[store.SessionDisconnectEventExtraKey])
	}
	if rec.CfgVersion != cfg || rec.AppliedCfg != cfg {
		t.Fatalf("(e) push minted a cfgversion: %q/%q", rec.CfgVersion, rec.AppliedCfg)
	}
	if rows := store.ClientSessions(rec); len(rows) != 1 || rows[0].Connected {
		t.Fatalf("rows after the disconnect = %+v, want the client disconnected", rows)
	}
	if len(se.calls) != 2 || se.calls[1].disconnects != 1 {
		t.Fatalf("hook calls = %+v, want the disconnect counted", se.calls)
	}

	// Sparse inform after: the event is one-shot, the plain noop returns.
	if jm = seInform(t, h, xkey, cfg, nil, nil); jm["_type"] != "noop" {
		t.Fatalf("post-push inform = %v, want noop (event is one-shot)", jm["_type"])
	}
}
