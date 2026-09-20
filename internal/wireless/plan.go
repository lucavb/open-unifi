package wireless

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/lucavb/open-unifi/internal/store"
)

// wlanBandDefault is the band value our admin API cannot express today.
// It maps to WlanConf "both": ONE vap per device radio (doc §8).
const wlanBandDefault = "both"

// SSIDOf resolves the on-wire SSID of a WLAN (SSID preferred over Name).
func SSIDOf(w Wlan) string {
	if w.SSID != "" {
		return w.SSID
	}
	return w.Name
}

func WlanID(d store.Device, w Wlan) string {
	if w.ID != "" {
		return w.ID
	}
	src := w.Name
	if src == "" {
		src = w.SSID
	}
	if src == "" {
		src = "vlan" + strconv.Itoa(w.VLAN)
	}
	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:])[:24]
}

// ---- stored radio data ----------------------------------------------------

// RadioRow is one device radio from the stored inform passthrough
// (the per-radio map under rec.Extra["radio_table"]).
type RadioRow struct {
	Name      string // radio_table "name" → phyname + parent + sort key
	Band      string // "radio" field: "ng" | "na" (default ng)
	BandKnown bool
	Raw       map[string]any
}

// StoredRadios extracts and sorts radios by name (sort key = `name`,
// config_int §141) from the device record's stored inform data. No radios →
// empty slice → the "no radio found" variant of the block (doc §1).
func StoredRadios(d store.Device) []RadioRow {
	rawList, ok := d.Extra["radio_table"].([]any)
	if !ok {
		return nil
	}
	var out []RadioRow
	for _, item := range rawList {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := JSONStr(m, "name", "")
		if name == "" {
			continue
		}
		band := JSONStr(m, "radio", "")
		known := band == "na" || band == "ng"
		out = append(out, RadioRow{Name: name, Band: band, BandKnown: known, Raw: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// JSONStr fetches a string field, formatting JSON scalars (float64 from
// decode) as their number form — "0", "42", "auto", …
func JSONStr(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			return t
		}
		return def
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return def
	}
}

// ---- admin-owned per-radio intent (CONTEXT.md trust policy) ----------------

// RadioIntentExtraKey is the record Extra key holding the admin-owned
// per-radio intent map, keyed by radio_table `name` (the same key the
// renderer and StoredRadios use). The literal is single-sourced in the
// store trust-policy registry (store.RadioIntentExtraKey, which record
// absorption guards): a device inform can neither write nor introduce it.
const RadioIntentExtraKey = store.RadioIntentExtraKey

// RadioIntent is the admin-owned provisioning intent for one radio's
// channel/txpower rows. Channel/Txpower hold the FORMATTED row value
// ("36", "0", "auto", … — the same normalization JSONStr applies to the
// device echo); "" means "no intent for this row — the device's
// radio_table echo survives verbatim" (CONTEXT.md: admin-owned rows sit
// on top, device-refreshable caps stay refreshable underneath).
type RadioIntent struct {
	Channel string
	Txpower string
}

// RadioIntents extracts the intent map from the record. Absent or empty
// yields nil (byte-identical render to a record without the layer);
// malformed shapes are skipped row-wise, never panic.
func RadioIntents(d store.Device) map[string]RadioIntent {
	raw, ok := d.Extra[RadioIntentExtraKey].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]RadioIntent, len(raw))
	for name, v := range raw {
		m, ok := v.(map[string]any)
		if !ok || name == "" {
			continue
		}
		it := RadioIntent{
			Channel: JSONStr(m, "channel", ""),
			Txpower: JSONStr(m, "txpower", ""),
		}
		if it.Channel != "" || it.Txpower != "" {
			out[name] = it
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// JSONBool fetches a boolean field (defaults false when absent).
func JSONBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// JSONInt fetches an integer field (numeric JSON scalars decode as
// float64); absent/non-numeric → 0.
func JSONInt(m map[string]any, key string) int {
	switch t := m[key].(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

// NumFromExtra reads a numeric Extra field (absent/non-numeric → known=false).
func NumFromExtra(extra store.JSONMap, key string) (bool, int64) {
	v, ok := extra[key].(float64)
	if !ok {
		return false, 0
	}
	return true, int64(v)
}

// WrapVID applies the doc §6 VLAN guard: vids ≤ 1 (0/absent, or the classic
// 1) join the mgmt bridge untagged, never br-trunk (documented deviation).
// SAFE-BY-CONSTRUCTION note (Lane A): the admin API and envelope loader
// validate VLAN ∈ 1..4094 upstream, so callers only reach here with
// pre-validated values; the ≤1/4094+ clamp is a belt-and-suspenders sink to
// the untagged mgmt bridge, never a silent re-tag of an invalid value.
func WrapVID(vid int) int {
	if vid < 2 || vid > 4094 {
		return 0
	}
	return vid
}

// ---- vap plan -------------------------------------------------------------

// VapPlan is one provisioned vap: an (enabled) WLAN instantiated on
// radio i, holding its bridge binding and devname.
type VapPlan struct {
	Wlan    Wlan
	ID      string
	RadioN  int // 1-based index into the sorted radio list
	Phyname string
	AthN    int // global 0-based counter → devname "ath<N>"
	Vid     int // 0 = untagged mgmt br0; 2..4094 tagged br0.<vid>
}

// PlanVaps builds the vap list in radio-sorted order (global wireless/aaa
// counter = list order; doc §2). Band default "both": one vap per radio.
func PlanVaps(d store.Device, wls []Wlan) ([]VapPlan, []RadioRow) {
	radios := StoredRadios(d)
	var vaps []VapPlan
	// NOTE: device vap_table devname reuse was considered (seeding the ath
	// counter from the device's reported vaps) and REJECTED as dead code —
	// the wire key is `name`/`radio_name`, not `devname`, so the block never
	// matched anything on a real AP. Revisit only with a capture-derived
	// fixture; do not re-key it without live evidence.
	ath := 0
	for i, r := range radios {
		if !r.BandKnown {
			continue
		}
		if JSONStr(r.Raw, "usage", "") == "uplink" && JSONStr(r.Raw, "mode", "") == "managed" {
			continue
		}
		for _, w := range wls {
			if !w.Enabled {
				continue // dropped with no trace (F.super line 44)
			}
			band := w.Band
			if band == "" {
				band = wlanBandDefault
			}
			if band == "2g" && r.Band != "ng" || band == "5g" && r.Band != "na" {
				continue
			}
			vaps = append(vaps, VapPlan{
				Wlan:    w,
				ID:      WlanID(d, w),
				RadioN:  i + 1,
				Phyname: r.Name,
				AthN:    ath,
				Vid:     WrapVID(w.VLAN),
			})
			ath++
		}
	}
	return vaps, radios
}

// UnknownBandRadios counts radio_table entries whose `radio` token is
// unrecognized (known provisioning bands are na/ng; the real token set is
// na/ng/6e/scan — skipping scan/6e is correct, but a WHOLE table of unknown
// tokens silently drops every WLAN, so callers log the count).
func UnknownBandRadios(d store.Device) int {
	n := 0
	for _, r := range StoredRadios(d) {
		if !r.BandKnown {
			n++
		}
	}
	return n
}

// ---- the provisioning plan -------------------------------------------------

// ProvisioningPlan is the single value computed from a device and the
// wireless envelope (CONTEXT.md: the provisioning plan). It carries the
// three things the inform path reads out of that (device, envelope) pair
// TOGETHER — the drift hash for the adoption engine's drift checks, the vap
// placements for the drift-settle confirmation bookkeeping, and the wireless
// rows (vaps + their sorted radios) for the system_cfg renderer — so all
// consumers of one decision answer from one computation and the drift hash
// can never disagree with the rows it pays for.
//
// The two prose invariants on the composition:
//
//   - renders-same ⇒ hashes-same: WlanListHash applies the renderer's
//     effective-value normalizations (radius/acct ports, vlan mode
//     spelling, inert profile gating), so a bytes-identical render mints
//     no drift — pinned in-package by the plan tests below and the
//     WlanListHash tests;
//   - its residuals: the DAS gate's DEVICE arm (fw_caps 0x100000,
//     systemcfg's supportsDasDad) is envelope-external, so on a record
//     without the bit a das flip mints a fresh hash over a
//     byte-identical render (documented on WlanListHash, bounded to one
//     idempotent full provisioning; the zz_* scratch gates remain the
//     live pins); and the WLAN list `name` hashes verbatim yet never
//     renders into a row while the SSID is set (SSIDOf prefers the
//     SSID), so a name-only spelling flip can mint a fresh hash over a
//     byte-identical render too — the reachable form is a fixed-ID
//     rename (UpdateWlan blocks name changes, and derived IDs hash-move
//     correctly because id joins the hash), name is an admin-identity
//     field, and the residual stays bounded to one idempotent full
//     provisioning.
//
// Placements keys SSID\x00radio_name → count, the shape the pending
// confirmation (applyProvisioning/settle) persists.
type ProvisioningPlan struct {
	DriftHash  string     // WlanListHash(wls) — the FSM drift input
	Vaps       []VapPlan  // vap plan in radio-sorted emission order
	Radios     []RadioRow // sorted radio_table rows (empty ⇒ no radio found)
	Placements map[string]int
}

// PlanProvisioning computes the provisioning plan: ONE constructor for the
// drift hash, the vap placements and the wireless rows, so no consumer
// re-derives any of them from a separate door.
func PlanProvisioning(d store.Device, wls []Wlan) ProvisioningPlan {
	vaps, radios := PlanVaps(d, wls)
	return ProvisioningPlan{
		DriftHash:  WlanListHash(wls),
		Vaps:       vaps,
		Radios:     radios,
		Placements: vapPlacements(vaps),
	}
}

// vapPlacements records the intended SSID-to-radio placements from the vap
// plan (SSID\x00radio_name → count) — the settle confirmation cannot be
// satisfied by a VAP on the wrong band/radio.
func vapPlacements(vaps []VapPlan) map[string]int {
	out := map[string]int{}
	for _, v := range vaps {
		out[SSIDOf(v.Wlan)+"\x00"+v.Phyname]++
	}
	return out
}

// ---- envelope hash (FSM drift input) ---------------------------------------

// WlanListHash serializes the wireless envelope stably (sorted-key JSON per
// item) and hashes it with sha256; the value is only compared against
// itself, so any stable canonicalization works.
//
// The inline RADIUS profile fields join the hash ONLY when set: a WLAN with
// no radius fields hashes byte-identically to the pre-radius format, so
// existing stored baselines (Extra["wlan_cfg_sha"]) do not spuriously drift
// across the upgrade. Server ports hash at their EFFECTIVE value (0 → the
// 1812 emission default), so a stored 0 and a stored 1812 — which render
// the same rows — also hash the same. The vlan mode hashes at its effective
// spelling too: "" normalizes to "disabled" (both render dynamic_vlan=0),
// so a spelling-only flip cannot mint a new hash. The band hashes at its
// effective spelling under the same rule: "" ≡ "both" place vaps
// identically (PlanVaps), so verbatim hashing let a spelling-only band flip
// mint a spurious drift push over a byte-identical render. The accounting
// fields follow the same effective-value rule one level coarser (see the
// inline comment): they join ONLY when accounting_enabled, because an inert
// profile renders byte-identically to none at all.
func WlanListHash(wls []Wlan) string {
	m := make([]map[string]any, 0, len(wls))
	for _, w := range wls {
		// Effective spelling, like the acct ports and the vlan mode below:
		// "" ≡ "both" place vaps identically (PlanVaps normalizes the same
		// way), so hashing the band verbatim let a spelling-only flip mint
		// a spurious drift push over a byte-identical render.
		band := w.Band
		if band == "" {
			band = wlanBandDefault
		}
		e := map[string]any{
			"name":       w.Name,
			"ssid":       w.SSID,
			"security":   w.Security,
			"passphrase": w.Passphrase,
			"vlan":       w.VLAN,
			"enabled":    w.Enabled,
			"id":         w.ID,
			"band":       band,
		}
		if len(w.RadiusServers) > 0 || w.RadiusSecret != "" || w.RadiusVLANMode != "" {
			e["radius_secret"] = w.RadiusSecret
			// Effective spelling, like the port normalization below: the
			// renderer maps "" and "disabled" to the same dynamic_vlan=0
			// row, so hashing the mode verbatim let a ""↔"disabled" flip
			// mint a spurious drift push over byte-identical system_cfg.
			mode := w.RadiusVLANMode
			if mode == "" {
				mode = "disabled"
			}
			e["radius_vlan_mode"] = mode
			servers := make([]map[string]any, 0, len(w.RadiusServers))
			for _, s := range w.RadiusServers {
				port := s.Port
				if port == 0 {
					port = 1812
				}
				servers = append(servers, map[string]any{"ip": s.IP, "port": port})
			}
			e["radius_servers"] = servers
		}
		// Accounting fields join the hash ONLY when accounting_enabled
		// (§12 rows 1013-1014): an inert profile — acct servers stored,
		// accounting off — renders byte-identically to a WLAN with no
		// accounting fields at all, so it must also hash the same (the
		// renders-same⇒hashes-same rule the radius block applies above);
		// otherwise flipping accounting off over unchanged rows would
		// mint a spurious drift push. Acct ports hash at their EFFECTIVE
		// value (0 → the 1813 emission default), and empty-IP slots DO
		// hash (unlike a skipped auth slot they still shift later row
		// indexes, so they are not render-inert). radius_das_enabled
		// joins under the same gate (§12 row 1014 implemented): with
		// accounting on, a das flip changes the emitted das/dad rows and
		// must mint a fresh sha. Residual: the das gate's device arm
		// (fw_caps 0x100000, render.go supportsDasDad) is outside the
		// envelope, so on a record without the bit a das flip mints a
		// fresh sha over a byte-identical render — bounded to one
		// idempotent full provisioning; the model set {U7PG2} carries
		// the bit (bench AP fw_caps 0xE7FD3F3F).
		if w.AccountingEnabled {
			e["accounting_enabled"] = true
			acct := make([]map[string]any, 0, len(w.AcctServers))
			for _, s := range w.AcctServers {
				port := s.Port
				if port == 0 {
					port = 1813
				}
				acct = append(acct, map[string]any{"ip": s.IP, "port": port})
			}
			e["acct_servers"] = acct
			e["interim_update_enabled"] = w.InterimUpdateEnabled
			e["radius_das_enabled"] = w.RadiusDASEnabled
		}
		m = append(m, e)
	}
	blob, err := json.Marshal(m) // map keys marshal in sorted order
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
