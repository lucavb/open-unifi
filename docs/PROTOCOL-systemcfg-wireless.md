# PROTOCOL-systemcfg-wireless — `radio.*` / `aaa.*` / `wireless.*` schema for a classic Atheros AP (U7PG2)

> **Open-unifi implementation note (2026-09-24):** The runtime fail-closed
> live-provisioning gate and `--allow-gated-live-wlan` were removed; managed
> WLANs and site-settings SSH keys are delivered on the normal inform loop.
> open-unifi emits a full synthetic `radio.*`/`aaa.*`/`wireless.*` block for
> the U7PG2 6.8.2.15592 baseline per §2-§7 below. Historical bench evidence
> (including the 2026-09-18 C1-shape round) is in
> `docs/WLAN-ACCEPTANCE-6.8.2.15592.md`.

Resolves UNRESOLVED item #1 of `docs/PROTOCOL-mgmt.md` §9 ("exact `wireless.<n>` line set").
Complements `docs/PROTOCOL-mgmt.md` §3 (where this block sits inside `system_cfg`)
and `docs/PROTOCOL.md` §5 (transport). Ground truth = CFR 0.152 decompiles of
`ace.jar`. Decompiles used here (all produced this session with the existing
toolchain, no `--renameillegalidents`): `decomp/configB_F.java` (`config/B/F` =
vap factory), `decomp/configB_M.java` (`config/B/M` = devname naming),
`decomp/WlanConf.java` (`com/ubnt/data/WlanConf` getters/defaults),
`decomp/configB_null.java` (class `B/null`), `B/P` (the `# dhcpc` writer),
`B/O0OO` (SAE psk-entry writer), `decomp/Device.java` (`isAtherosAP`,
`supportOpenHostapd`, `hasWifiCapability`), enums `com/ubnt/model/api/wlan/*`,
`com/ubnt/data/Chipset` + `Model` (bean dispatch), plus the established
`config_int.java` / `config_String.java`.

**Provenance (decompilation artifacts):** the `decomp/…` file names throughout
this doc family refer to the original proguard-renamed `.java` outputs of the
CFR decompiler, produced in a **local, untracked decompilation workspace** —
there is no `decomp/` directory in the tracked tree. The source jar lives at
`tmpwork/data/usr/lib/unifi/lib/ace.jar` and the canonical, reproducible
bytecode citations are the `javap -c -v` dumps under `tmpwork/javap/**` (also
gitignored by design, since the decompiled controller jar is Ubiquiti's
copyrighted artifact). Keep this in mind when following any `decomp/…`
reference: it is reproducible only from the same jar dump, not from git.

## 0. U7PG2 really takes the `ath`/`wifi` (atheros·madwifi) branch

- `nullsuper.\u00f4o0000(Device)` → `isAtherosAP()` → bean `_if`
  (config_nullsuper.java §296-299; also PROTOCOL-mgmt.md §1).
- `Device.isAtherosAP()` = `model.getChipset().typeOf(Chipset.\u00f800000) &&
  getType() == DeviceType.\u00d200000` (decomp/Device.java §768-770); constant
  pool of `Chipset` puts `ATHEROS` first (javap `ldc "ATHEROS"`, int `m\u00f800000`).
- `Model` bytecode for U7PG2: `ldc "U7PG2" … getstatic Chipset.ATHEROS`
  (model_javap2, `Model.<clinit>` region) ⇒ U7PG2 is an ATHEROS `uap`.
- Bean `config/if` ctor passes `int._o.String`; in `int._int(...)`:
  ```java
  this.O\u00f50000 = _o2 == _o.String;   // atheros naming: ath<N>, parent wifi<N>
  this.\u00d2\u00f50000 = _o2 == _o.\u00d300000; // broadcom naming (wl<0|1>.<idx>)
  this.supernull  = _o2 == _o.o00000;    // third flavor (IEEE-country 12 IEEE80211?)
  ```
  (config_int.java §167-171 + ctor §182-185). Every branch below assumes
  `O\u00f50000 == true` for U7PG2.

## 1. Entry chain (inside `int.\u00d300000(Device)`, the system_cfg builder)

```
int.\u00d300000(Device)                        config_int.java §1878 (PROTOCOL-mgmt.md §3)
└─ cfr_renamed_1(dev, mgmtX, radios, wlans, vaps, vlans, ifaces, trunkIfs, mixIfs, mgmtNet)
   = int §1229-1460    ← WLAN collection + athdev allocation + bridge/vlan merge
     - radios  = device.getRadioTable() duplicated + sorted by field "name" (§1255)
     - query   = {site_id, ap_group_ids} → List<WlanConf> (§1271; empty when device disabled)
     - band filter per radio: w.getWlanBand().isOnRadio(radioName) (§1273)
     - vWire/mesh/element synthetic wlans appended to the same list (§1317-1382)
     - per vap: F.super(wlanConf, device, radio)     config/B/F §43-72
       → M.o00000(wlanConf, radio, globalIdx, perRadioIdx, parentName, true, false, false)  §1385/§1470
       → puts athdev, radio, radio_name, radio_nx, parent, vapIdxOnRadio        §1395-1399
       → bridge merge: String.cfr_renamed_0(bridges, vlanStr, athdev, is_guest,
         is_trunk, is_mgmt)                             config_String.java §105-126
     - after the rt loop: String.\u00d400000(dev, bridges, names) assigns each br_name  §469-492
└─ cfr_renamed_1(sb, device, radios, wlans, vaps)   = int §466-735   ← THE EMITTER (this doc)
     then, later in int.\u300000's own call order (§1960-2004):

     String.cfr_renamed_0(sb, dev, ifaces, vlanIds) → "# vlan"    config_String §429-443
     String.\u00d200000(sb, dev, bridges)            → "# bridge"   config_String §494-515
     String.cfr_renamed_0(sb, dev, …)                → "# netconf"  config_String §551-593
     config/B/P.o00000(sb, dev, guestFlag, bridges)  → "# dhcpc"    B/P decomp §29-45
```

Emitter header (`int` §488-497) is always exactly:

```
# wlans (radio)
radio.status=enabled
radio.countrycode=840
aaa.status=enabled
wireless.status=enabled
radio.outdoor=disabled|enabled
```
(country = site setting `country.code` default `"840"`; `radio.outdoor` from
`outdoor_mode_override`+site `outdoor_mode_enabled` §498-500.)
If the device has no radios: `# no wlan provisioned as no radio found` +
`radio.status=disabled` and the block ends (int §489-493).

## 2. WLAN enumeration, indexing, disabled WLANs

- **Disabled WLANs are dropped with no trace** — `config/B/F.super(...)` line 44
  (`decomp/configB_F.java`):
  ```java
  if (!wlanConf.isEnabled()) { return null; }   // isEnabled() = is("enabled", true)
  ```
  Also dropped (F §47-70 + helpers): UID-IoT without `supportWpaPpsk()`;
  hotspot2/OSEN without `supportHotspot2()`; WPA3/OWE variants the device cannot
  handle (capability helper `oOOO(radio)`); non-`isWpa3LegacyEnabled` fallbacks
  get downgraded (`fast_roaming` off, `wpa3_transition` off) rather than dropped.
  ⇒ no `status=disabled` line is ever emitted for a WLAN; absence is the flag.
- **Per-band instantiation**: a WLAN appears once per band its `wlan_band`
  covers (`WlanBand` enum = `{2g, 5g, both, unknown}`; int §1273 filter).
- **Index semantics**:
  - `radio.<n4>`: 1-based per radio, in radios sorted by their `name` field
    (radios sort key = `name`, `new C._oOo("name", true)` — config_int §141).
  - `wireless.<n>` / `aaa.<n>`: **one 1-based counter across all vaps in
    radio-sorted order** (`n7` in the emitter at §545-550: increment once per
    vap per radio).
  - `athdev` (`devname`): `config/B/M` dispatch (all branches javap-verified):
    ```java
    // madwifi bean flavor (U7PG2):
    devname = (wlanConf.is("is_wds_downlink") ? "vwire" : "ath") + N;   // N = GLOBAL counter, 0-based
    // broadcom flavor:      "wl<0|1>.<perRadioIdx>"  (eth1-wifi0 → 0 else 1); perRadioIdx 0 ⇒ radio name
    // mt76 style:           name-minus-last-char + perRadioIdx, or "apcli0"/"apclii0" for wds uplink
    // else:                 "unknown"
    ```
    so on U7PG2 the first vap overall is **ath0**, the next **ath1**, … one
    monotonic counter that continues across radios and also across the OWE twin
    vap (`owe_devname`, int §1414-1422).
  - `wireless.<n>.devname` and `aaa.<n>.devname` both carry that `athdev`
    string; device-side binding is by `devname` + `id=<WlanConf._id>`, NOT by
    index.
- **Index stability**: indices and `athdev` are recomputed on every provision
  push; nothing persists them (checked: no writes to these keys elsewhere in
  `int`). WLAN order within a radio = order of the query result (the site WLAN
  table query `C("site_id", siteId).\u00d500000("ap_group_ids", ids)` — see §8
  note on ordering).

### 2.1 Vap-set assembly before per-WLAN emission: no-radio guard + hidden synthetic vaps (2026-09-17 night pass)

The 10-parameter collector (`super(Device, X, List<X>, List<WlanConf>, List<X>,
Set<Integer>, List<String>, List<X>, List<String>, X)` — int.txt:L12629, Code
int.txt:L12632, javap offsets 0–2874; args: dev, mgmtX, radios_out, wlans_out,
vapXs_out, vlanIds, wdsAthdevs, bridges, mixedIfs, mgmtNet) is where a render's
vap SET is assembled: site WLANs plus up to three kinds of synthetic vap the
controller invents. The main entry `int.\u00d300000(Device)` (int.txt:L16860)
calls it (call offset 494) and then hands `wlans_out` to the 6-parameter
emitter (int.txt:L5489; call offset 767). "collector §N" below = javap offset
inside this method's Code.

- **No-radio guard (collector §109)**: `radio_table` empty ⇒ return; the
  render then carries no `wireless.*`/`aaa.*` rows at all. That is the only
  early-out — there is no WLAN-less-radio guard here: a radio with zero
  surviving WLANs still gets its §3 `radio.<n4>` core rows (emitted per radio
  unconditionally), but no vap rows or companions of its own.
- **Site gates (collector §0–103)**: `local15 = device.supportVwire() &&
  connectivitySetting.is("enabled", true)` — supportVwire() = wifi_caps mask 1
  (Device.txt:7706-7714; live record wifi_caps=559857373=0x215EBEDD ⇒ bit 0
  SET), and the site `connectivity` Setting defaults enabled ⇒ TRUE in the
  normal site shape. `local16 = device.is("mesh_sta_vap_enabled", false)` ⇒
  FALSE normally. `element_adopt` = site Setting
  `"element_adopt".is("enabled", false) && device.supportElement()` ⇒ FALSE
  normally.
- **Per-radio synthesis** (inside the per-radio loop, collector §284–2250):
  - `create_vport` (put at collector §771 ⇒ `radio.<n>.mode=managed`, §3):
    set iff `local15 && local16 && (device.supportMultiVport() || radio is NA)`
    ⇒ normally FALSE ⇒ `radio.<n>.mode=master`. This is the real-builder
    mechanism behind the §12 `radio.<n>.mode` deviation row.
  - vwire branch gate: `local38 = local15 && !device.is("disabled", false) &&
    radio.is("vwire_enabled", true)` ⇒ TRUE normally.
  - **mesh vap (collector §962–1103)**: when `local38 &&
    device.supportMeshv3()` (wifi_caps mask 2048 — SET on U7PG2,
    0x215EBEDD), the collector appends a mesh WlanConf per radio
    UNCONDITIONALLY: security=WPA_PSK, wpa_mode=WPA2, wpa_enc=ccmp,
    is_wds_downlink=true, hide_ssid=true, name=connectivity.getString(
    "x_mesh_essid"), x_passphrase=connectivity.getString("x_mesh_psk"),
    radio=<band>. It survives the §2 B/F instantiation filter (drops only
    disabled/uid-iot/hotspot2) ⇒ emits `wireless.<n>`/`aaa.<n>` rows with
    `usage=downlink` (§5) and devname `vwire<N>` (§2 athdev rule:
    is_wds_downlink ⇒ "vwire"+N).
  - **`vport-<serial>` vap (collector §868–962)**: when create_vport set:
    is_wds_uplink=true, hide_ssid=true, radio=<band>, PREPENDED (`add(0, …)`)
    ⇒ devname `ath<N>`, `usage=uplink`. The factory-baked default config
    (harness ap-forensics/tmp/system.cfg, `mgmt.is_default=true`) corroborates
    the shape: `aaa.2.ssid=vport`/`aaa.2.devname=ath1`, `wireless.2`
    usage=uplink vport=enabled wds=enabled mode=managed security=none,
    `radio.2.mode=managed` — the firmware baked the vport vap shape as its
    factory default.
  - **`vwire-<serial>` peer vap (collector §1104–1821)**: only when the
    device `vwire_table` (X.\u00d3o0000) filtered to this radio's band is
    non-empty AND `wds_peers` resolves non-empty (§1802): x_vwirekey =
    32-char generate(), AES-encrypted payloads (x_authkey default
    "ba86f2bbe107c7c57eb5f2690775c712" then OOoO.\u00d200000 hex-decode,
    C.o00000 AES), wep_idx=4, wds_peers list. Absent on wired-uplink APs
    (empty vwire_table ⇒ no peer vap; §1804 add never taken).
- **Real renders on this U7PG2** (derived from instantiation order — per radio
  the site WLANs (query order) instantiate, then the appended mesh vap; one
  global 0-based counter across radios): a 2g-only site WLAN yields
  ng = [user `ath0`, mesh `vwire1`], na = [mesh `vwire2`]; both-band yields
  `ath0`, `ath1`, `vwire2`, `vwire3`. Every WLAN-count change therefore also
  changes the bridge port list (eth0 + every untagged vap, mesh included) —
  true of the real builder with or without our deviation; see
  WLAN-ACCEPTANCE-6.8.2.15592.md §Bridge-apply verdict.
- **AirView path (not ours)**: `int.\u00d400000(Device)` (int.txt:L17624) →
  5-parameter collector (int.txt:L14090) synthesizes `vport-<serial>` per radio
  with spectrum_enabled=true, security=OPEN — the spectrum/AirView
  provisioning path; recorded so L14090's vport rows are not misread as the
  main render.
- **ours**: planVaps emits vaps only for site WLANs
  (internal/wireless/plan.go:159-198); zero synthesis. This is byte-faithful
  to the real builder's vwire-disabled site shape (site connectivity
  `enabled=false` ⇒ local15 false ⇒ zero synthetics on the real path too).
  §12 records the deviation.

## 3. `radio.<n4>` rows (one per device radio; `int` §518 — single verbatim call)

| key (`radio.<n4>.` prefix) | default | source |
|---|---|---|
| `phyname` | – | device radio_table `name` (`x6.getString("name", this.O\u00f50000 ? "wifi0" : "eth1")`, §1269) |
| `ack.auto` | disabled | device radio field `ackauto` variant key (§516 via `cfr_renamed_1(key, device, radio)`) |
| `acktimeout` | 64 | same helper, default `64` (int §516-517) |
| `ampdu.status` | enabled | literal |
| `clksel` | 1 | literal |
| `countrycode` | `840` | site country code (setting `country.code`) |
| `cwm.enable` | 0 | literal |
| `cwm.mode` | 1 iff `chanWidth != 20 && radio=="ng"` else 0 | §514-515, width via `com.ubnt.service.devmgr.c.cfr_renamed_2(radio, countrycode)` |
| `forbiasauto` | 0 | literal |
| `channel` | 0 = auto | radio_table `channel`; open-unifi: admin intent overlay wins (§3.2) |
| `backup_channel` | 0 | radio_table `backup_channel` |
| `ieee_mode` | `11n` | `_int.cfr_renamed_1(isNg, chanWidth)` §737-743 = `"11n" + (isNg ? "g" : "a") + "ht" + <width>`; width = `devmgr/c` resolver: **min(country limit, HT-mode cap, device-reported caps)** — RESOLVED, see §3.1 |
| `mode` | master | `managed` only when a vport wds-aplink is provisioned on this radio (`create_vport`, §1310) |
| `rate.auto` | enabled | literal |
| `rate.mcs` | auto | `\u00f4\u00f40000 = "auto"` (int §151) |
| `rfscan` | disabled | radio_table `spectrum_enabled` |
| `bcmc_l2_filter.status` | enabled | site/X `config.mcast_filter_enabled` default true |
| `bgscan.status` | disabled | literal |
| `antenna.gain` | 0 | `builtin_antenna ? builtin_ant_gain : antenna_gain` (default 6 absent, §510) |
| `antenna` | -1 | radio_table `antenna_id` (default -1) |
| `txpower_mode` | auto | radio_table `tx_power_mode` (default "auto", const #252; read int.txt 5687-5691, emitted as row `txpower_mode` int.txt 5942-5949 — the row name drops the underscore); never intent-driven (§3.2, resolved §9) |
| `txpower` | auto | radio_table `tx_power` (default "auto"; read int.txt 5692-5696, emitted as row `txpower` int.txt 5950-5958); open-unifi: admin intent overlay wins (§3.2) |
| `hard_noisefloor.*` | `status=disabled` | when `sens_level_enabled` + advanced: `enabled, max_sens=-40, minrssi.value=…, minrssi_backoff=0` (§519-525) |
| `stamgr.<n4>.*` | (separate key, radio-index) | only when `advanced_feature_enabled` + any of min-rssi/load-balance: `status=true, radio=ng, minrssi.status, minrssi.rssi, loadbalance.status, loadbalance.maxsta` (§527-531) |

Per-vap companion rows (int:6124-6204, javap `com__ubnt__service__config__int.txt`):
the jar emits a `devname`+`status` row pair for **EVERY vap** on the radio — the
`.virtual.<d>` suffix is only inserted when `vapIdxOnRadio > 0`:
```
radio.<n4>.devname=athX                (first vap on the radio: plain `radio.<n4>` prefix)
radio.<n4>.status=enabled
radio.<n4>.virtual.<vapIdxOnRadio>.devname=athY          (2nd+ vap only)
radio.<n4>.virtual.<vapIdxOnRadio>.status=enabled
```
(An earlier revision claimed these rows exist only for vapIdx>0; the bytecode loop
at com__ubnt__service__config__int.txt:6124-6204 shows the loop runs per vap over
the whole vap list and only switches to the `.virtual.<d>` prefix when
`WlanConf.getInt("vapIdxOnRadio", 0) > 0`.)

### 3.1 RESOLVED — the `radio.<n>.ieee_mode` `<ht>` width resolver (was §9 UNRESOLVED)

An earlier revision claimed the resolver class was never decompiled. It is — it is
`com.ubnt.service.devmgr.c` (javap dump `tmpwork/javap/com__ubnt__service__devmgr__c.txt:1242-1380`,
full class verified). Semantics, from the bytecode:

```java
int resolve(X radio, String countrycode) {                  // c.new(X,String), :1242-1296
    X country = find in system R.forfloat() list by {code, countrycode};  // :1247-1292
    int  bandLimit = countryLimit(radio.getString("radio", "ng"), country);  // :1307
    int  htCap     = radio.getInt("ht", radio.radio == "ng" ? 20 : 40);     // :1249-1268 — ng→20, na→40 MHz default
    int  devCap    = deviceCaps(radio);                      // :1382-1415
    return Math.min(Math.min(bandLimit, htCap), devCap);
}

int countryLimit(String band, X country) {                   // o00000(String,X), e.g. :1463-1518
    // widest w with a non-empty country record list `channels_<band>_<w>`:
    // tries w=2160→1080→160→80→40→20; empty everywhere → 20
}

int deviceCaps(X radio) {                                   // o00000(X), :1382-1415
    if (radio.radio == "ad")                    return 2160;
    if (radio.is("has_ht160", false))           return 160;
    if (radio.is("is_11ac", false) || radio.is("is_11ax", false)) return 80;
    return radio.is("spectrum_enabled", false) ? 20 : 40;    // rf-scan (AirView) forces 20
}
```

The emitter (`int.cfr_renamed_1(isNg, width)`) then renders `"11n" + (ng?"g":"a") +
"ht" + <width>`. For a `UAP-AC-Pro-Gen2` (U7PG2 = 11n radios: no `is_11ac`/`is_11ax`,
no `has_ht160`, `ht` fields unset ⇒ ng cap 20 / na cap 40, device caps 40/40) the
resolver yields **`11nght20` on the ng radio and `11naht40` on the na radio**
(country limits permitting) — replacing the earlier `<UNRESOLVED>` placeholder and
the "`11nght20/11naht20` TODO" in `docs/PROTOCOL.md` §7.

open-unifi status: aligned in this change (Go builder now implements min(3 caps)
instead of a hardcoded `20`).

### 3.2 Admin-owned per-radio intent overlay (open-unifi extension; 2026-09-19)

The jar source for every `radio.<n>` row is the device's radio_table echo — the
classic controller never stores an admin channel/txpower wish for U7PG2 in any
field this decompile set exposes. The 2026-09-19 txpower packet verified this
for the tx rows by constant-pool sweep (§9): every ref to the
`tx_power_mode`/`tx_power` strings in `config.int` is consumed at the pure
echo sites (int.txt 5687-5696 → 5942-5958) and `config.String` carries no
tx_power/txpower strings at all — no controller-side writer for these rows
exists anywhere in the config classes. open-unifi adds one admin-owned record
field (the device record's `Extra["radio_intent"]`) that the renderer overlays
on two rows of §3, so an admin's saved radio setting survives every inform
echo and is what actually ships:

| row | jar default/source (§3) | with intent overlay |
|---|---|---|
| `radio.<n>.channel` | radio_table `channel` echo, default `0` (auto) | `Extra["radio_intent"][radioName]["channel"]` wins when present; `0` = explicit auto |
| `radio.<n>.txpower` | radio_table `tx_power` echo, default `auto` | `Extra["radio_intent"][radioName]["txpower"]` wins when present; `"auto"` or fixed dBm |
| `radio.<n>.txpower_mode` | radio_table `tx_power_mode` echo, default `auto` | **never intent-driven — and never was on the jar side either**: no controller-side writer for this row exists in the config classes (constant-pool sweep: every ref to the `tx_power_mode`/`tx_power` strings — Utf8 #1695/#1697, row names #1729/#1730 — is consumed at the pure echo sites int.txt 5687-5696 → 5942-5958; `config.String` carries no tx_power/txpower strings at all; resolved-as-echo §9) |

Semantics (Go contract, `internal/wireless.RadioIntents` +
`internal/server/systemcfg` renderer):

- Intent is keyed by **radio_table `name`** (`ra0`/`rai0`, not `radio.2`), so a
  device-side radio_table reorder/refresh cannot redirect the overlay.
- A radio with no intent entry (or an empty layer) renders byte-identical to a
  record with no `radio_intent` key at all — `{}` and absent are the same state,
  and malformed entries are skipped row-wise (never panic, echo still wins).
- Setting an intent is an **operator save**: the app bumps the device's
  cfgversion (fresh 16-hex) once per effective change; the next inform's default
  engine arm (`AppliedCfg != CfgVersion`) delivers it via full provisioning.
- Admin validation (409 on violation): `channel` ng `0..14`, na `0` or
  `36..165`; `txpower` fixed values must fit the device-reported
  `min_txpower..max_txpower` bounds; `"auto"` is always valid on ng/na; any
  intent on an unknown band token is rejected rather than shipped unvalidated.
  Country-specific channel legality (e.g. DFS) is intentionally NOT re-validated
  — that is the device/jar's job; the jar's recovered DFS-legality machinery
  and its open linkage points are recorded in §9.

## 4. Per-WLAN `aaa.<n>` rows (order = call order in the emitter)

### 4.1 Always-first block (int §566-578)
```
aaa.<n>.pmf.status=disabled|enabled       (PmfMode != DISABLED; forced disabled when vWire flags set, §563-565)
aaa.<n>.pmf.mode=0|1|2                    PmfMode enum: disabled=0 optional=1 required=2 (javap values)
aaa.<n>.ft.status=disabled|enabled        isFastRoamingEnabled()
aaa.<n>.log_level=<int>                   only when wlanConf.getInt("log_level") >= 0
aaa.<n>.country_beacon=disabled|enabled   is("country_beacon", false)
aaa.<n>.11k.status=disabled|enabled       is("rrm_enabled", false)
```

### 4.2 OPEN / WEP branch (security `open`|`wep`; int §587-594)
```
aaa.<n>.br.devname=<br devname hosting this vap, fallback literal "br0">
aaa.<n>.devname=ath<X>
aaa.<n>.driver=madwifi                      (atheros branch)
aaa.<n>.ssid=<wlan name>                    (wlanConf.getString("name"))
aaa.<n>.status=enabled|disabled             ← `this.cfr_renamed_1(wlanConf, device)`: true iff !is_wds_uplink &&
                                              (device.supportOpenHostapd() || wlanConf.isWPA2())
                                              (int §2126-2134). For OPEN + wifi-caps bit 0x2000 absent → disabled.
aaa.<n>.id=<WlanConf._id>
// WEP only:
aaa.<n>.security=wep64|wep128|aes128        (_int.OO0000 by psk length: 10→wep64, 26→wep128, other→aes128)
aaa.<n>.security.<wep_idx>.key=<psk>        (plain x_wep; 5/13-char ASCII pre-hexed by com.super.A.OOoO.\u00d300000; null → "wrong")
aaa.<n>.security.default_key=<wep_idx>
```
Open+WPA3 transitional adds the `wpa3.support/transition` writer call
(`this.\u00d8\u00f40000.o00000(sb, wlanConf, "aaa."+n, legacyEnabled)` §589-591).
No `wpa.*` lines in this branch.

### 4.3 WPA branch: PSK + EAP (int §595-612)

WPA-EAP is a supported open-unifi security: the Wlan carries an inline
RADIUS profile (admin API `radius_servers` = auth servers, `radius_secret`
= the profile-level `x_secret`, `radius_vlan_mode` = `vlan_wlan_mode`,
plus the accounting fields `accounting_enabled`/`acct_servers`/
`interim_update_enabled`/`radius_das_enabled` — §12 rows 1013-1014;
`radius_das_enabled` is accepted behind its requires-accounting gate
(das/dad rows implemented, §12 row 1014),
accepted ONLY with ≥1 auth server and a shared secret
(adminapi.validateWlanEap — the jar's `requireRadiusProfile()` gate,
int §13492+; a profile-less EAP row is rejected at the API, and a
profile-less envelope built outside it still renders with a renderer
Alert, mirroring the jar's invalid-profile warn path that ships a dead
vap). Fixed block (§597, one `C.o00000` call with pairs → each pair becomes one row):
```
aaa.<n>.br.devname=…        aaa.<n>.devname=ath<X>       aaa.<n>.driver=madwifi
aaa.<n>.ssid=<name>         aaa.<n>.status=enabled        (only is_wds_uplink → "disabled")
aaa.<n>.verbose=2                                        (4 on debug builds, R.\u00d8\u00d2O000())
aaa.<n>.wpa=<int>                                        WpaMode.getMode(): WPA1=1, WPA2=2, AUTO=3 (AUTO ctor passes iconst_3 — WpaMode static-init javap, `com__ubnt__model__api__wlan__WpaMode.txt:197-211`); default when `wpa_mode` unset is AUTO ⇒ **3**
aaa.<n>.eapol_version=1|2                                1 iff WPA1 else 2 (enum getEapolVersion)
aaa.<n>.wpa.group_rekey=3600                             getInt("group_rekey", 3600)
aaa.<n>.p2p=disabled / .p2p_cross_connect=disabled / .proxy_arp=disabled
aaa.<n>.is_guest=true|false
aaa.<n>.tdls_prohibit=disabled
aaa.<n>.bss_transition=enabled
aaa.<n>.id=<WlanConf._id>
```

**WPA-Personal** — psk writer (int §759-766):
```java
String mgmt = "WPA-PSK";
C.o00000(sb, "aaa." + n,
    {"wpa.key.1.mgmt", mgmt, "wpa.psk", wlanConf.getWpaPreSharedKey()});
```
```
aaa.<n>.wpa.key.1.mgmt=WPA-PSK
aaa.<n>.wpa.psk=<x_passphrase>   ← PLAINTEXT. getWpaPreSharedKey() = getString("x_passphrase","letmeinnow") (WlanConf.java §308-311)
```
Ciphers (int §610-611):
```
aaa.<n>.wpa.1.pairwise=CCMP        WpaEncryption.getRsnGroup(wpaMode, !isWpa3):
                                   AUTO → "CCMP", or "TKIP CCMP" iff wpa_mode==WPA1; else wpa_enc name upper-cased
aaa.<n>.pmf.cipher=AES-128-CMAC    PmfCipher default AUTO → cipher string "AES-128-CMAC"
```
WPA3/SAE variant adds: `wpa.key.1.mgmt=SAE`, `wpa3.support/transition` rows and
per-PSK entries via `config/B/O0OO` (`sae.sync`, `sae.groups.<i>.group`,
`sae.psk.<i>.psk/.mac/.vlan/.id`) — cited, not part of the MVP contract.

**WPA-Enterprise (`wpaeap` / `osen`)** — int §775-789, RADIUS helper
§791-840. Emitted by open-unifi for `security=wpa-eap` (OSEN is not an
admin-API option). Row status per line:
```
aaa.<n>.wpa.key.1.mgmt=WPA-EAP               (OSEN → "OSEN"; not modelled) — EMITTED
aaa.<n>.wpa.psk=<x_passphrase>               (same fallback "letmeinnow"; admin API passphrase is OPTIONAL on wpa-eap, ≥8 chars when set) + auth_cache=enabled — EMITTED (auth_cache literal "enabled", the is(..., true) default)
aaa.<n>.radius.auth.<i>.ip/.port=1812/.secret=<x_secret>     EMITTED: i=1..4, row index = position in radius_servers, empty-ip slot skipped with NO backfill, entries past slot 4 never emit; port 0 → 1812; secret = radius_secret (profile-level x_secret) on every row (servers from wlanConf auth_servers, via radiusprofile copyAttrsIfPresent int §1401-1405)
aaa.<n>.radius.acct.<i>.ip/.port=1813/.secret=<x_secret>     EMITTED (2026-09-19 acct lane, §12 row 1013): per profile accounting server when `accounting_enabled`; i=1..4 by ARRAY POSITION in acct_servers, empty-ip slot skipped with NO backfill, entries past slot 4 never emit; port 0 → 1813; secret = radius_secret (profile-level x_secret) on every row — the accounting server carries no secret of its own
aaa.<n>.radius.dad.status=enabled/.dad.port=3799 + .das.status=enabled/.das.port=<3800+n>/radius.dad.status=enabled   EMITTED (2026-09-19 das/dad flip, §12 row 1014): gated on `accounting_enabled` && `radius_das_enabled` && the device fw_caps 0x100000 bit (hasCapability(1048576), int 1500-1539). The dad block (dad.status, dad.port=3799 literal) emits ONCE PER DEVICE RENDER (int 197-228, the cross-wlan once-flag local 19); the das block then emits das.status, das.port=3800+n, and dad.status AGAIN on every emitted index (int 234-299) — the duplicate is the jar's own byte shape
aaa.<n>.radius.dad.client.<i>.cidr=<ip>/32 + .secret=<x_secret>   EMITTED (2026-09-19 das/dad flip, §12 row 1014): per accounting server at the SAME slot i as radius.acct.<i>; the `<ip>` is the server bean's own admin-configured field (X.getString(srv,"ip","") + "/32", int 670-692); secret = radius_secret (profile-level x_secret)
aaa.<n>.radius.das.client=<ip> / .das.secret=<x_secret>       EMITTED (2026-09-19 das/dad flip, §12 row 1014): once per aaa index from the FIRST non-empty-IP accounting server (jar local 8, int 302-303/527-604); secret = radius_secret
aaa.<n>.interim_update.status=enabled / .interval=<3600>     EMITTED (2026-09-19 acct lane, §12 row 1014): when `accounting_enabled` AND `interim_update_enabled`; interval is the jar's 3600 default — the inline profile carries no interval knob
aaa.<n>.dynamic_vlan=0|1|2                    EMITTED: radius_vlan_mode ""/disabled→0, optional→1, required→2 (jar default 0)
aaa.<n>.radius_acct_send_keyid.status=enabled  OMITTED (Uid IoT + psk-radius gates not modelled — §12)
aaa.<n>.filter_id=UID_WIFI                    OMITTED (Uid wifi + radius_filter_id_enabled + supportsRadiusFilter gates not modelled — §12)
```
Static VLAN wiring note: under `radius_vlan_mode` optional/required the
vap KEEPS its static `vlan` wiring (§6 rows unchanged) — per-sta dynamic
assignment is device-side RADIUS behavior; the controller-side DAS/DAD
rows that complement it stay omitted (§12).
Common tail for both wpa kinds (int §613-624), then:
```
aaa.<n>.radius.macacl.status=enabled|disabled             (radius_mac_auth_enabled)
aaa.<n>.radius.macacl.emptypassword=disabled|enabled      (radius_macacl_empty_password)
aaa.<n>.radius.macacl.format=<mac format>                 (from WlanConf.RadiusMacAclFormat)
aaa.<n>.hide_ssid=true|false                              (NOTE: hide_ssid emitted on BOTH aaa and wireless)
aaa.<n>.hs20.…                                            (hotspot2 sub-writer, int §842-1101; status=disabled when off)
aaa.<n>.iapp_key=<wlanConf.getIappKey()>                  (only when iapp_enabled != true; default enabled → skip)
```

## 5. Per-WLAN `wireless.<n>` rows (int §628-685 — verbatim key set with defaults)

```java
[0..1]   "mode"        is_wds_uplink ? "managed" : "master"
[2..3]   "devname"     athdev
[4..5]   "id"          wlanConf.getString("_id")
[6..7]   "status"      LITERAL "enabled"       ← disabled WLANs are filtered upstream (F.super line 44)
[8..9]   "authmode"    (security==OPEN && !wds_uplink) ? "0" : "1"
[10..11] "l2_isolation" enabled iff is("l2_isolation", is_guest-default)
[12..13] "is_guest"    true|false
[14..15] "security"    WEP ? (wep64|wep128|aes128) : "none"
                       ⚠ even for WPA-PSK / WPA-EAP this is LITERAL "none"; security lives only in aaa.<n>.wpa.*
[16..19] "security.<wep_idx>.key", "security.default_key"   (WEP only; filtered when null)
[20..21] "addmtikie"   "disabled"
[22..23] "ssid"        wlanConf.getString("name")   (same value as `name`)
[24..25] "hide_ssid"   isHidden() = is("hide_ssid", false)
[26..27] "mac_acl.status"  "enabled"   (literal — always)
[28..29] "mac_acl.policy"  "deny"      (literal — policy lives in the macacl section, int §1751-1778)
[30..31] "wmm"         "enabled"
[32..33] "uapsd"       disabled|enabled (uapsd_enabled)
[34..35] "parent"      wlanConf.getString("parent", O\u00f50000 ? "wifi0" : "eth1")
                       — parent was set by the collector to the RADIO TABLE's device name (§1399)
[36..37] "puren"       "0"
[38..39] "pureg"       is("b_supported", false) ? "0" : "1"
[40..41] "usage"       WlanUsage.toString(): uplink|downlink (wds) else guest|user
[42..43] "wds"         enabled iff any wds flag
[44..45] "mcast.enhance"  0|1 (mcastenhance_enabled)
[46..47] "autowds"     "disabled"
[48..49] "vport"       enabled iff is_wds_uplink
[50..51] "vwire"       enabled iff is_wds_downlink
[52..53] "schedule_enabled" enabled|disabled (isScheduleEnabled())
[54..55] "no2ghz_oui"  disabled|enabled (dedup helper int §462)
```
Follow-ups (int §686-729, condition-gated):
```
wireless.<n>.element_adopt=disabled|enabled            (is("element_adopt"))
wireless.<n>.dgaf_disable=…                            (hotspot2conf_enabled only)
wireless.<n>.mcastrate=auto|<str>                      (device radio override, else wlanConf mcast_rate default "auto")
wireless.<n>.mgmt_rate=<str>                           (override key "mgmt_rate" present)
wireless.<n>.bcast.enhance=<str>                       (override key present)
wireless.<n>.bga_filter=disabled|enabled               (device.hasWifiCapability(64); disabled for wds)
wireless.<n>.schedule_invert=enabled                   (schedule reversed & feature)
wireless.<n>.schedule_<off|on>[.<i>]=<from>-<to>       (sec-resolution schedule strings; supportMultiBlockWlanSchedule appends index)
wireless.<n>.dtim_period=3                             (dtim_mode custom → dtim_<radio> field)
wireless.<n>.minrate_data / beacon_rate / mgmt_rate    (minrate_<band>_enabled off → skipped;
                                                        element_adopt ng → 6000/6000/6000 + minrate_cck_rates.status=false;
                                                        ng rates default 1000..54000, na 6000..54000 — WlanConf.forif / \u00d2\u00d2O000)
wireless.<n>.minrate_below_disable / minrate_cck_rates.status   (advertising)
wireless.<n>.bcfilt.status=enabled / .bcfilt.<i>.{status,mac}    (bc_filter_enabled + bc_filter_list, int §1780-1791)
wireless.<n>.vwirepayload / vwirepeers / vwirepayload_bcast     (vWire only)
wireless.<n>.debug=0x90c81440                          (debug builds only, is("config.…"? no: flag R.\u00d8\u00d2O000()))
```

## 6. VLAN wiring for a WLAN — decision code (int §1425-1456, verbatim)

```java
boolean dynVlanEap   = wlanConf2.isEAP()
    && !"disabled".equals(wlanConf2.getString("vlan_wlan_mode", "disabled"));
Optional<NetworkConf> net = <int-field B-type>.o00000(wlanConf2, allNetworks);   // networkconf_id / ip-range lookup
boolean dynVlan      = <helper>.o00000(net);          // network has ip ranges → radius dynamic vlan
boolean hasStaticVlan = <helper>.o00000(wlanConf2);   // wlanConf has a vlan_id/networkconf_id bound
boolean vlanEnabled  = !dynVlanEap && (dynVlan || hasStaticVlan);
boolean mgmtOverride = x2.is("enabled", false);       // x2 = device.mgmt_network_id report (\u200d4O0000(device), int §1202-1211)

x3.put("vlan_enabled", vlanEnabled adjusted-against-mgmt);
if (vlanEnabled) {
    int vid = dynVlan ? net.get().getInt("vlan", 2) : wlanConf2.getInt("vlan", 2);
    if (mgmtOverride && vid == mgmtVlan) vlanEnabled = false;      // avoid tagging onto mgmt vlan
    String.cfr_renamed_0(bridges, String.valueOf(vid), athdev, is_guest, /*trunk*/false, /*mgmt*/false);
    vlanIds.add(vid);                     // feeds the "# vlan" section
} else if (mgmtOverride && !listTrunkIfs.contains(athdev)) {
    String.cfr_renamed_0(bridges, "1", athdev, is_guest, /*trunk*/true, /*mgmt*/false);   // join br-trunk (trunk vid=1)
} else {
    String.cfr_renamed_0(bridges, "0", athdev, is_guest, false, /*mgmt*/true);            // join mgmt br0 untagged
}
```
Bridge naming (String.\u00d400000, config_String §469-492 — verbatim):
```java
if (is_mgmt)       br_name = "br0";
else if (is_trunk) br_name = "br-trunk";
else               br_name = "br0." + vlan;         // String.cfr_renamed_0(int) = "br0."+n
```
Trunk vid constant: `public static int \u00f4\u00f40000 = 1;` with
`String.\u00d300000(n) = \u00d200000(n) ? "br-trunk" : "br0."+n`
(config_String §69-84, §517-527). ⇒ **a WLAN tagged with VID 1 silently lands on
the trunk bridge**, go guard it.

What a tagged WLAN pulls in (each emitted by its own writer, rows share no
counter with `wireless.<n>`):

| block | row shape | emitter |
|---|---|---|
| `# vlan` | `vlan.<i>.devname=<eth iface>`, `vlan.<i>.id=<vid>` — nested (vlanIds × ethIfaces) loops | config_String §429-443 |
| `# bridge` | `bridge.<j>.devname=br0.<vid>`, `.fd=1`, `.stp.status=disabled`, `bridge.<j>.port.<k>.devname=ath<X>` | config_String §494-515 |
| `# netconf` | `netconf.<l>` per netconf-inventory instance (instance skipped when `name` is null): `status=enabled` (literal, FIRST row), `devname=<name>`, `ip=<ip, default 0.0.0.0>`, `autoip.status=disabled` (literal), `netmask=<null-filtered>`, `promisc=<null-filtered lookup>`, `up=<up, default enabled>` | config_String §551-593 (javap offsets 4694-4764) |
| `# dhcpc` | guest wlan on a tagged bridge: `dhcpc.<m>.status=enabled, .ip_only=true, .devname=br0.<vid>` | config/B/P §29-45 |
| `aaa.<n>.br.devname` | = br_name of the bridge containing the athdev (search §556-561), fallback literal "br0" | int §555-561 |

## 7. Worked example — U7PG2, `country.code=840`

Device: `radio_table = [{name:"ra0", radio:"ng", channel:"0", tx_power_mode:"auto",
tx_power:"auto", builtin_antenna:true, builtin_ant_gain:0},
{name:"rai0", radio:"na", channel:"0", …}]`. Radios sorted by name ⇒ ra0=radio 1,
rai0=radio 2. Site WLANs:

| | WLAN a | WLAN b |
|---|---|---|
| name | corp | guest |
| security | wpapsk | open |
| wpa_mode / wpa_enc | wpa2 / ccmp | – |
| x_passphrase | correcthorse | – |
| vlan | 42 | – |
| enabled | true | **false** |
| is_guest | false | true |
| hide_ssid | false | false |
| wlan_band | both | (would have been both) |

Emitter output (only wireless/aaa/vlan/bridge/netconf/dhcpc scope; attribute
order within each `C.o00000` call is preserved):

```
# wlans (radio)
radio.status=enabled
radio.countrycode=840
aaa.status=enabled
wireless.status=enabled
radio.outdoor=disabled

# radio loop (n4 = 1 per radio in sorted order)
radio.1.phyname=ra0
radio.1.ack.auto=disabled
radio.1.acktimeout=64
radio.1.ampdu.status=enabled
radio.1.clksel=1
radio.1.countrycode=840
radio.1.cwm.enable=0
radio.1.cwm.mode=0
radio.1.forbiasauto=0
radio.1.channel=0
radio.1.backup_channel=0
radio.1.ieee_mode=11nght20                  (resolver §3.1: 11n AP, ng band → 20 MHz)
radio.1.mode=master
radio.1.rate.auto=enabled
radio.1.rate.mcs=auto
radio.1.rfscan=disabled
radio.1.bcmc_l2_filter.status=enabled
radio.1.bgscan.status=disabled
radio.1.antenna.gain=0
radio.1.antenna=-1
radio.1.txpower_mode=auto
radio.1.txpower=auto
radio.1.hard_noisefloor.status=disabled
# per-vap companions: EVERY vap gets `radio.<n4>.devname`+`radio.<n4>.status`;
# `.virtual.<d>` suffix only when vapIdxOnRadio>0 (int.txt:6124-6204)
radio.1.devname=ath0
radio.1.status=enabled
# radio.2.* = same field set; phyname=rai0, ieee_mode=11naht40 (§3.1), antenna values per na row
radio.2.devname=ath1
radio.2.status=enabled

# vap corp on ng → wireless.1 / aaa.1 / ath0 (global counter starts at 0)
aaa.1.pmf.status=disabled
aaa.1.pmf.mode=0
aaa.1.ft.status=disabled
aaa.1.country_beacon=disabled
aaa.1.11k.status=disabled
aaa.1.br.devname=br0.42                       (corp vap joins the VLAN-42 bridge)
aaa.1.devname=ath0
aaa.1.driver=madwifi
aaa.1.ssid=corp
aaa.1.status=enabled
aaa.1.verbose=2
aaa.1.wpa=2
aaa.1.eapol_version=2
aaa.1.wpa.group_rekey=3600
aaa.1.p2p=disabled
aaa.1.p2p_cross_connect=disabled
aaa.1.proxy_arp=disabled
aaa.1.is_guest=false
aaa.1.tdls_prohibit=disabled
aaa.1.bss_transition=enabled
aaa.1.id=<WlanConf._id>
aaa.1.wpa.key.1.mgmt=WPA-PSK
aaa.1.wpa.psk=correcthorse
aaa.1.wpa.1.pairwise=CCMP
aaa.1.pmf.cipher=AES-128-CMAC
aaa.1.radius.macacl.status=disabled
aaa.1.hide_ssid=false

wireless.1.mode=master
wireless.1.devname=ath0
wireless.1.id=<WlanConf._id>
wireless.1.status=enabled
wireless.1.authmode=1
wireless.1.l2_isolation=disabled
wireless.1.is_guest=false
wireless.1.security=none                      (⚠ literal even for WPA-PSK)
wireless.1.addmtikie=disabled
wireless.1.ssid=corp
wireless.1.hide_ssid=false
wireless.1.mac_acl.status=enabled
wireless.1.mac_acl.policy=deny
wireless.1.wmm=enabled
wireless.1.uapsd=disabled
wireless.1.parent=ra0
wireless.1.puren=0
wireless.1.pureg=1
wireless.1.usage=user
wireless.1.wds=disabled
wireless.1.mcast.enhance=0
wireless.1.autowds=disabled
wireless.1.vport=disabled
wireless.1.vwire=disabled
wireless.1.schedule_enabled=disabled
wireless.1.no2ghz_oui=disabled
wireless.1.element_adopt=disabled
wireless.1.mcastrate=auto
wireless.1.dtim_period=3

# vap corp on na → wireless.2 / aaa.2 / ath1: identical row set with
#   aaa.2.devname=ath1 (same br.devname=br0.42), wireless.2.devname=ath1, parent=rai0;
#   the site WLAN's _id is the SAME on both rows (band instantiation duplicates the conf).
# (No `radio.<n>.virtual.*` lines here because vapIdxOnRadio == 0 on each radio —
#  the companions are plain `radio.<n4>.devname/.status` for the first vap,
#  see §3 note at int.txt:6124-6204.)

# WLAN b (guest, enabled=false) → NOTHING. decomp/configB_F.java §44:
#   "if (!wlanConf.isEnabled()) return null;"   — no wireless.3 / aaa.3 / ath2 /
#   no bridge entry, no dhcpc row. (This is the dropped-WLAN signal.)

# vlan section (from the merged collector: vlanIds={42}, ethIfaces={eth0})
vlan.1.devname=eth0
vlan.1.id=42

# bridge section (mgmt br0 with its untagged eth port(s); plus br0.42 with the corp vaps)
bridge.1.devname=br0
bridge.1.fd=1
bridge.1.stp.status=disabled
bridge.1.port.1.devname=eth0
bridge.2.devname=br0.42
bridge.2.fd=1
bridge.2.stp.status=disabled
bridge.2.port.1.devname=ath0
bridge.2.port.2.devname=ath1

# netconf (excerpt only; full inventory includes eth0 ip, br0, br0.42 …)
# (row order per config_String §551-593 / javap 4694-4764: status is a literal
#  "enabled" and always the FIRST row of the instance; netmask and promisc are
#  null-filtered lookups; ip defaults to 0.0.0.0, up defaults to enabled.)
netconf.<k>.status=enabled
netconf.<k>.devname=br0.42
netconf.<k>.ip=0.0.0.0
netconf.<k>.autoip.status=disabled
netconf.<k>.netmask=<null-filtered>
netconf.<k>.promisc=<null-filtered; promisc bridges carry enabled>
netconf.<k>.up=enabled

# dhcpc — the `# dhcpc` header + `dhcpc.status=enabled` are ALWAYS emitted
# (B/P.txt o00000, config__B__P.txt:162-176). Additionally, whenever the device's
# netconf is DHCP (`config_network.type` != "static"; default "dhcp"), a
# mgmt-interface row with BOTH keys is emitted: `dhcpc.<m>.status=enabled` +
# `dhcpc.<m>.devname=<Device.getMgmtDev()>` (config__B__P.txt:178-217). Guest-vlan
# bridge rows (guestFlag caller arg) also carry both keys + ip_only: see §6.
# (In this example the device IP is assumed DHCP, and the guest WLAN is disabled,
# so the only occurrence is the mgmt row.)
dhcpc.status=enabled
dhcpc.1.status=enabled
dhcpc.1.devname=<getMgmtDev() of the device>


# (adjacent sections, out of excerpt scope: "# bandsteering", "# airtime fairness",
#  "# stamgr", "# qos", "# mac acl", "# mesh", "# connectivity" — order per
#  PROTOCOL-mgmt.md §3.)
```

## 8. Admin-API field → system_cfg mapping (Go contract)

| our Wlan field | WlanConf source | drives |
|---|---|---|
| `name` | `name` (same value used for `ssid`) | `wireless.<n>.name`/`ssid`, `aaa.<n>.ssid` |
| `security=open` | `security=open` | NO `aaa.<n>.wpa.*`; `wireless.<n>.authmode=0`, `security=none`; `aaa.<n>.status` = enabled iff device `wifi_caps` bit `0x2000` (`supportOpenHostapd`, Device.java §1275 & §1247) — **device-record dependent; check per adopter** |
| `security=wpa-p` | `security=wpapsk` (wpa_mode AUTO→3, wpa_enc AUTO→CCMP) | `aaa.<n>.wpa=3` (AUTO; jar truth — WPA1=1/WPA2=2/AUTO=3, WpaMode static-init `WpaMode.txt:197-211`), `.eapol_version=2`, `.wpa.key.1.mgmt=WPA-PSK`, `.wpa.psk=<passphrase>` (plaintext), `.wpa.1.pairwise=CCMP`, `.pmf.cipher=AES-128-CMAC`, `.wpa.group_rekey=3600`, `wireless.<n>.authmode=1`, `security=none` |
| `security=wpa-eap` | `security=wpaeap` + a valid radiusprofile (requireRadiusProfile, int §13492+) | `.wpa.key.1.mgmt=WPA-EAP`, `.psk=<passphrase or the "letmeinnow" fallback — passphrase optional, ≥8 when set>`, `auth_cache=enabled`, `radius.auth.<i>.*` per `radius_servers` (i=1..4, port 0→1812, secret=`radius_secret`), `dynamic_vlan` per `radius_vlan_mode`, `wireless.<n>.authmode=1`, `security=none`. Without a profile the API rejects the row; the renderer flags an envelope built outside the API with a dead-vap Alert. `radius.acct.<i>.*` rows per `accounting_enabled` + `interim_update.*` rows per `interim_update_enabled` + the das/dad rows per `radius_das_enabled` (all behind the accounting gate, §12 rows 1013-1014 implemented — the das gate also requires the device fw_caps 0x100000 bit); keyid/filter_id rows omitted (§12 row 1015) |
| `radius_servers` (wpa-eap only; 1..4 entries) | radiusprofile `auth_servers` (copied onto the wlanConf, int §1401-1405) | `aaa.<n>.radius.auth.<i>.ip` + `.port` (0→1812); row index = ARRAY POSITION (empty-ip slot skipped, no backfill, no 5th slot — the API rejects both, renderer defense mirrors the jar) |
| `radius_secret` (wpa-eap only) | radiusprofile `x_secret` | `aaa.<n>.radius.auth.<i>.secret` verbatim on EVERY server row — never hashed/obfuscated (the radius writers follow the psk-writer rule); also `aaa.<n>.radius.acct.<i>.secret` on every acct row (the doc's `<x_secret>` symbol, §12 row 1013) |
| `radius_vlan_mode` (wpa-eap only) | `vlan_wlan_mode` (""/disabled/optional/required) | `aaa.<n>.dynamic_vlan` = 0/1/2; static `vlan` wiring (§6) unchanged under optional/required — per-sta assignment is device-side |
| `accounting_enabled` (wpa-eap only) | radiusprofile `accounting_enabled` (§12 row 1013) | gates the `aaa.<n>.radius.acct.<i>.*` rows; with accounting off the render is byte-identical to a WLAN with no accounting fields at all (stored `acct_servers` stay inert, renderer goldens pin the identity; the drift hash follows the same rule — inert servers hash as none). Accepted with zero acct servers: the radiusprofile stores toggle and server list independently |
| `acct_servers` (wpa-eap only; 0..4 entries) | radiusprofile `acct_servers` (§12 row 1013) | `aaa.<n>.radius.acct.<i>.ip` + `.port` (0→1813) + `.secret=radius_secret`; row index = ARRAY POSITION, empty-ip slot skipped, no backfill, no 5th slot (auth-row slot semantics mirrored, §12 row 1013) |
| `interim_update_enabled` (wpa-eap only; requires `accounting_enabled`) | radiusprofile `interim_update_enabled` (§12 row 1014) | `aaa.<n>.interim_update.status=enabled` + `aaa.<n>.interim_update.interval=3600` (the jar's default — the inline profile carries no interval knob); unreachable without accounting (the jar's own gates, §12 row 1014 rationale), hence rejected at the API when accounting is off |
| `radius_das_enabled` (wpa-eap only) | radiusprofile `radius_das_enabled` (§12 row 1014) | ACCEPTED behind the requires-accounting gate (2026-09-19 das/dad flip): with accounting on, the renderer emits the dad block (dad.status, dad.port=3799) once per device render plus das.status/das.port=3800+n/dad.status per emitted aaa index, and the client rows from the acct servers' own `ip` fields (das.client/das.secret once per index; dad.client.<i>.cidr=`<ip>`/32/.secret per server slot); a record without the fw_caps 0x100000 bit renders no das/dad rows — the silent jar shape for a no-capability device |
| `passphrase` | `x_passphrase` (fallback literal `"letmeinnow"`) | `aaa.<n>.wpa.psk` verbatim — **never hashed/obfuscated on this writer** |
| `vlan=<vid>` | `vlan` (or bound `networkconf_id`) | new `br0.<vid>`: `# vlan` row(s), `# bridge` row + `port.*.devname=ath…`, `# netconf` row, `aaa.<n>.br.devname=br0.<vid>`; guard `vid != 1` (else br-trunk). Applies unchanged to wpa-eap WLANs — the `radius_vlan_mode` dynamic-VLAN row only labels the vap; per-sta assignment is device-side RADIUS behavior, and the controller-side DAS/DAD rows stay omitted (BLOCKED, §12 row 1014). |
| `vlan` absent/0 | – | `aaa.<n>.br.devname=br0`; no `# vlan`/bridge additions; (device mgmt-network overridden → joins br-trunk, §6) |
| `enabled=false` | `enabled` | **entire WLAN omitted** (F.super return null ⇒ no vap, no bridge membership, no dhcpc row) |
| `enabled=true` | `enabled` | vap + all rows above with `wireless.<n>.status=enabled` (literal) |
| hidden | `hide_ssid` | `aaa.<n>.hide_ssid` AND `wireless.<n>.hide_ssid` |
| guest | `is_guest` | `aaa.<n>.is_guest=true`, `wireless.<n>.is_guest=true`, `usage=guest`, `l2_isolation` defaults to enabled, plus `dhcpc.<m> ip_only=true devname=br0.<vid>` for its bridge |
| `wlan_band` | `wlan_band` (2g/5g/both) | how many vaps the WLAN gets (one per band on the device) |
| schedule | `schedule_*`, `schedule_enabled` | `wireless.<n>.schedule_enabled` + `schedule_<off|on>[.<i>]=<from>-<to>` rows |

Defaults the Go builder must reproduce (`WlanConf.java` getters, cited):
`hide_ssid=false`, `b_supported=false` ⇒ `pureg=1`, `group_rekey=3600`,
`dtim=3`, `wpa_enc=auto` ⇒ `CCMP`, `wpa_mode=auto` ⇒ `wpa=3 / eapol 2`
(WpaMode AUTO ctor passes `iconst_3` — `com__ubnt__model__api__wlan__WpaMode.txt:197-211`),
`x_passphrase` fallback `"letmeinnow"`, `auth_cache=true` (EAP),
`vlan_wlan_mode=disabled` ⇒ `dynamic_vlan=0`.

### 8.1 Per-radio admin intent → `radio.<n>` rows (open-unifi; 2026-09-19)

`PUT/DELETE /api/v1/devices/{mac}/radios/{radio}` writes the admin-owned
`Extra["radio_intent"]` layer (§3.2); `GET /api/v1/devices/{mac}/radios` reads
it back. The upsert body is wholesale-replace (like the wireless envelope):
absent/null fields clear the radio's previous intent.

| API field | stored as | drives |
|---|---|---|
| `channel: <int>` | `radio_intent[radioName].channel` (float64) | `radio.<n>.channel` (intent wins over echo) |
| `channel: 0` | same (explicit auto) | `radio.<n>.channel=0` overriding a non-default echo |
| `txpower: "auto"` | `radio_intent[radioName].txpower = "auto"` | `radio.<n>.txpower=auto` |
| `txpower: <int dBm>` | `radio_intent[radioName].txpower` (float64) | `radio.<n>.txpower=<dBm>` (bounds-checked against device-reported min/max) |
| absent / `null` / `DELETE` | entry cleared; empty layer key dropped | echo-only render (byte-identical to pre-feature records) |

A cfgversion bump (operator save) rides on every *effective* change; idempotent
writes don't bump. Validation and delivery semantics are in §3.2.

## 9. UNRESOLVED / explicitly searched & not found

- **Radio-intent lane omissions (2026-09-19)** — no new `radio.<n>` row shapes
  were minted; the admin intent overlay (§3.2) reuses the recovered
  `radio.<n>.channel`/`txpower` rows verbatim. Deliberately NOT implemented
  (see `docs/WLAN-ACCEPTANCE-6.8.2.15592.md` radio-lane obligations):
  - ~~`radio.<n>.txpower_mode` admin semantics~~ **RESOLVED as pure echo
    (2026-09-19 txpower lane)**: the classic controller has NO admin
    semantics for this row — no controller-side writer for
    `radio.<n>.txpower_mode` (or `radio.<n>.txpower`) exists in the config
    classes. Evidence (txpower packet, transcribed by the fleet parent from
    the `com__ubnt__service__config__int.txt` javap dump): the only reads
    are `X.getString("tx_power_mode","auto")` / `X.getString("tx_power",
    "auto")` off the device's radio_table entry — no setter, no admin
    lookup, no controller-side override (int.txt 5687-5696, default const
    #252 "auto"); the row emitter pairs those locals with the
    underscore-less row names `txpower_mode`/`txpower` (int.txt 5942-5958,
    array slots 40-43); and the constant-pool sweep found every ref to Utf8
    #1695/#1697/#1729/#1730 consumed at those echo sites, while
    `config.String` holds no tx_power/txpower refs at all. How (or whether)
    the real controller ever flips `tx_power_mode` is therefore outside the
    config classes — nothing in this evidence settles it, so minting an
    admin meaning for the row remains forbidden (acceptance radio-lane
    obligation 4: no bench observation may mint it without a jar citation
    first). open-unifi leaves the row as the pure echo, pinned by
    `internal/server/systemcfg/render_txpower_test.go`.
  - Country channel legality (DFS/passive) beyond the ng `0..14` / na
    `36..165` band bounds: the admin API still enforces only band bounds —
    but the 2026-09-19 txpower packet recovered the jar's DFS-legality
    MACHINERY, superseding the earlier "no analogous channel-legality
    resolver surfaced" note:
    - Read-side gate `int.super(String, List<X>)` (int.txt 16774-16845):
      resolves the country row via `X.findOne` over the registry list
      (`R.forfloat()`; site `country.code`, default `"840"` = US, `"124"` =
      Canada; no country row ⇒ false), reads its `channels_na_dfs` integer
      list (empty ⇒ false), selects the capability word `has_fccdfs` for
      US/CA vs `has_dfs` for any other country (int.txt 1017-1021), and
      returns true iff any radio row both carries the selected capability
      word and has a channel inside the NA-DFS list.
    - Backing data: `channels_na_dfs` is a country-table field with a static
      fallback (com__ubnt__service__devmgr__c.txt 1222-1232, signature at
      line 1240); `has_dfs`/`has_fccdfs` appear in the device capability
      word lists (com__ubnt__service__devmgr__i.txt 6612-6629 and
      6288-6304; com__ubnt__service__devmgr__IA.txt 2330-2345 and
      2652-2668).
    - Guarded dfs-reset cron row (com__ubnt__service__config__String.txt
      5204-5242): the cron/mgmt emitter carries a guarded block emitting
      `cron.1.job.<n>` with `status=enabled`, `schedule=0 2 * * *`,
      `cmd=syswrapper.sh dfs-reset` (pool refs String.txt 400-408, 985-994),
      sharing its job counter with the schedule-action /
      refresh-walled-garden / 11k-scan rows emitted just above. The guard
      local's producer is NOT transcribed — its link to the read-side gate
      above is PLAUSIBLE BUT UNPROVEN (recorded open point, not a claim).
      The dfs-reset cron rows are evidence for the legality story only,
      NOT a render deliverable: open-unifi emits no dfs-reset row (the
      factory baseline carries none).
    - What remains unsettled: the packet does not show the gate's CALLER —
      whether that boolean feeds `radio.<n>.channel` emission, admin-side
      validation, or neither is unproven. Controller-side channel legality
      for the `radio.<n>` rows is therefore still NOT re-validated by
      open-unifi; the device rejects illegal channels at apply time.
  - The `{radio}` restart set: never live-evidenced (every live round so far
    restarted `{wireless, aaa}`). The successive-push channel-intent zz gate
    (added 2026-09-19) must run live once before the first production
    channel-intent push.
  The javap index under `tmpwork/javap/` was unreadable during the original
  radio-intent lane (sandbox denial), so that lane's §3 citations were taken
  from the existing decompile text files; no jar bytes were re-derived. The
  2026-09-19 txpower lane had javap access ONLY through the fleet parent's
  embedded packet — a verbatim transcription of the same `tmpwork/javap/`
  dumps (config int / config String / devmgr c / devmgr i / devmgr IA) —
  and every txpower-lane citation above is a packet line number,
  reproducible from the same jar dump.

- ~~`radio.<n>.ieee_mode` `<ht>` value~~ **RESOLVED** (moved to §3.1): the resolver
  class `com/ubnt/service/devmgr/c.class` is now decompiled
  (`tmpwork/javap/com__ubnt__service__devmgr__c.txt:1242-1380`); semantics =
  min(country limit, HT-mode cap ng→20/na→40, device-reported caps). Earlier
  revision wrongly stated "the class was not decompiled in this pass" — superseded.
- `<int-field B-type>.o00000(wlanConf, networks)` resolver class identity
  (Optional<NetworkConf> provider used in §6): field declared `protected final B
  \u00f6\u00f40000` (int §165) — but the decompile named `com.ubnt.service.config.B`
  shows only the mgmt_cfg method; the store of this helper is therefore ambiguous
  between CFR renames. Semantics (vlan resolution, dynamic-vlan 0/1/2 output,
  `WlanBand` handling) are pinned by the code *bodies*, not the type name.
- `com.ubnt.service.schedule.OOoO` `<from>-<to>` string exact format (seconds
  vs HH:mm) — not decompiled; only row shape is confirmed (int §1117-1127).
- Hotspot-2.0 full `aaa.<n>.hs20.*` field list — writer exists (int §842-1101),
  out of scope (no hotspot2 in admin API contract).
- WPA3/SAE (`config/B/O0OO`) and OWE-twin-vap (`int` §1414-1422) key set —
  cited, not expanded (not in admin API).
- `device.wifi_caps` bit dictionary beyond {64=bga_filter, 128=mesh,
  0x100000=RADIUS-DAS, 4096=radius-mac-auth, 0x2000=open-hostapd} — not
  enumerated.
- **Cross-check against an independent source**: the enum defaults and defaults
  cited above all come from `com/ubnt/data/WlanConf` + `com/ubnt/model/api/wlan/*`
  decompiles (Security/WpaMode/WpaEncryption/PmfCipher/PmfMode/WlanUsage/
  WpaPskRadius/WlanBand) — i.e. a second artifact chain (model-api enums) agreeing
  with the builder code. Optional third source (live `unifi` config dump) is not
  available in this lane; recommend flagging a real device cfg capture as the
  final acceptance test.

## 10. Addendum — byte-exact `users.1` password format (closes the fix-7 assumption)

This pins PROTOCOL-mgmt.md §3 item 2/8 (`# users` block). Everything below was
re-derived this session from bytecode (no `--renameillegalidents`).

### 10.1 The emitter (decomp/config_String.java §184-205, verbatim)

```java
void \u00d300000(StringBuilder stringBuilder, Device device) {
    java.lang.String string = device.supportsSsh()
        ? (device.supportsSha512Password()
              ? this.\u00f600000.\u00d4O0000(device)     // L sha-512 helper
              : this.\u00f600000.\u00f500000(device))    // L md5 helper
        : this.\u00f600000.\u00d800000(device);          // L legacy (no SSH fw support) helper
    C.o00000(stringBuilder, "# users", new String[0]);
    C.o00000(stringBuilder, "users.status", {"enabled"});
    C.o00000(stringBuilder, "users.1",
        {"name",   this.\u00f600000.\u00f400000(device),   // L.<user> — see 10.5
         "password", string,                          // ONE of the three hashes below
         "status",  enabled});                        // \u00d8\u00d50000 = "enabled"
    C.o00000(stringBuilder, "users.2",
        {"name","nobody","password","x","shell","/bin/false","status","enabled"});
}
```
So the users.1 block is exactly three rows (`users.1.name`, `users.1.password`,
`users.1.status`) — **no `users.1.shell` row is emitted for user 1** (only
`users.2.shell=/bin/false` exists).

### 10.2 Which hash is chosen (Device.java, cited)

- `Device.supportsSsh()` = `!isNuvotonSwitch()` (Device.java §1217).
- `Device.supportsSha512Password()` = `hasCapability(1024)` OR
  `getDeviceType() == DeviceType.\u00f500000` (Device.java §1193-1196), where
  `hasCapability(n) = (n & device.fw_caps) == n` (§1204-1206) — fw_caps comes
  from the device record, i.e. U7PG2 with `fw_caps & 0x400` ⇒ **SHA-512 branch**.

### 10.3 SHA-512 branch (the U7PG2/mainstream path) — **`$6$` glibc crypt, NOT plain hex**

`com.ubnt.service.config.L.\u00d4O0000(Device)` (decomp/com__ubnt__service__config__L.java
§213-229, verbatim):

```java
public String \u00d4O0000(Device device) {
    Setting setting = this.Object.\u00d500000("mgmt", device.getString("site_id"));
    String string  = setting.getString("x_ssh_password", "ubnt");
    String string2 = setting.getString("x_ssh_sha512passwd", "unknown");
    boolean bl = false;
    try {
        bl = string2.equals(C.\u00f500000((String)string, (String)string2));   // crypt(pw, storedHash as salt) self-check
    } catch (RuntimeException ignore) {}
    if (!bl) {
        string2 = C.\u00f4O0000((String)string);                              // crypt(pw) — fresh random salt
        this.Object.o00000("mgmt", device.getString("site_id"),
            (Map)new X(new Object[]{"x_ssh_sha512passwd", string2}));          // cache back into site setting
    }
    return string2;
}
```
`com.ubnt.ace.C` (decomp/ace_C.java §868-876, verbatim):
```java
import org.apache.commons.codec.digest.Crypt;          // ace_C.java line 148
public static String \u00f4O0000(String string) { return Crypt.crypt((String)string); }
public static String \u00f500000(String s, String s2) { return Crypt.crypt((String)s, (String)s2); }
```
The jar's bundled **commons-codec-1.11.jar** decides the format
(`javap` of `org/apache/commons/codec/digest/Crypt` and `Sha2Crypt`, verified):

- `Crypt.crypt(byte[])` → `Sha2Crypt.sha512Crypt(bytes)` (bytecode: `aconst_null` …
  `Sha2Crypt.sha512Crypt:([B)`).
- `Sha2Crypt.sha512Crypt(byte[])` → null-salt path builds
  `ldc "$6$"` + `B64.getRandomSalt(8)` then
  `sha2Crypt(key, "$6$"+salt, "$6$", 64, "SHA-512")`.

⇒ **Byte-exact: `users.1.password = "$6$" + <8 salt chars> + "$" + <86-char sha512crypt hash>`,
e.g. `$6$ABCDEFGH$dL9yVKzEzwCtTXFDqH/z1W6G/gA`-style glibc SHA-512 crypt string.**
No `rounds=` parameter is appended (fresh generation always uses the default
round count); the salt alphabet is commons-codec's B64 set (`./0-9A-Za-z`).
Long-form: total string length = 106 chars. NOT a plain-hex digest.

### 10.4 MD5 branch (SSH-capable but `!(fw_caps & 0x400)`) — `$1$` md5crypt

`L.\u00f500000(Device)` (L decomp §231-247):
```java
String string2 = setting.getString("x_ssh_md5passwd", "unknown");
boolean bl = string2.equals(?) verified via ooOO.cfr_renamed_1(string, string2);
if (!bl) {
    string2 = ooOO.o00000((String)string, (String)RandomStringUtils.randomAlphabetic(8));
    save to site mgmt "x_ssh_md5passwd";
}
return string2;
```
`ooOO` = `com.super.A.ooOO` (the in-jar Apache-md5crypt port; decompiled verbatim,
`decomp/super_A_ooOO_MD5Crypt.java`):
```java
public static final String o00000(String string, String string2) {
    return ooOO.o00000(string, string2, "$1$");          // magic line §26
}
```
(also exposes `$apr1$` via `new()`/`\u00d300000` — unused by L). The md5crypt
implementation truncates the salt to 8 chars, salt input here is
`RandomStringUtils.randomAlphabetic(8)` (letters only).

⇒ **Byte-exact: `users.1.password = "$1$" + <8 salt chars (alphabetic)> + "$" + <22-char md5crypt hash>`**.

### 10.5 Username row

`L.\u00f400000(Device)` / static `L.oO0000(Device)` (L decomp §195-200 + §260-262):
```java
public String \u00f400000(Device device) {
    if (device.isUbios()) return L.oO0000(device);
    Setting setting = this.Object.\u00d500000("mgmt", device.getString("site_id"));
    return setting.getString("x_ssh_username", L.oO0000(device));
}
public static String oO0000(Device device) { return device.isUbios() ? "root" : "ubnt"; }
```
⇒ `users.1.name` = site `mgmt.x_ssh_username` or default **`ubnt`** (root on UBios).

### 10.6 Legacy branch (`!supportsSsh()`, e.g. Nuvoton) — DES crypt

`L.\u00d800000(Device)` (L decomp §208-211):
```java
return C.\u00f500000((String)setting.getString("x_ssh_password", "ubnt"), (String)"ui");
```
`Crypt.crypt(bytes, "ui")` — `"ui"` matches none of the `$6$/$5$/$1$` magic
prefixes (`javap` dispatch of `Crypt.crypt(byte[],String)`), so commons-codec
falls through to `UnixCrypt.crypt(bytes, salt)`.

⇒ **Byte-exact: 13-char classic DES crypt: `"ui" + <11 DES chars>`** (`ui` is the
fixed salt).

### 10.7 Net for the Go builder

```
matches site mgmt setting:
  x_ssh_sha512passwd cached → reuse verbatim (regex-check with commons SALT_PATTERN
                              ^\$([56])\$(rounds=(\d+)\$)?([./0-9A-Za-z]{1,16}).* before trusting)
  else generate: "$6$" + 8×salt("./0-9A-Za-z") + "$" + sha512crypt(pw)   [default pw "ubnt"]
fallback (no fw_caps bit, non-AP fw): "$1$" 8 char alpha salt… or 13-char DES for pre-SSH devices.
```
First fix-7 assumption ("plain hex SHA-512") is **wrong in format but identical in
spirit**: both are SHA-512-based, but the wire format is glibc `$6$salt$hash`. 

> **open-unifi divergence (recorded 2026-09-23) — users.1.password source.**
> jar: the password is SITE-WIDE — `mgmt.x_ssh_password` (default `ubnt`),
> cached in the same site setting (`x_ssh_sha512passwd`). open-unifi: the
> password is a PER-DEVICE record field (`store.Device.SSHPassword`, admin
> intent via PATCH `/api/v1/devices/{mac}`); the wire row mechanics are the
> jar's own. An EMPTY record password = stop managing: the render reuses the
> last controller-pushed well-formed cache row VERBATIM (a byte-stability
> device, exactly like the jar's `x_ssh_sha512passwd` cache self-check) — a
> device whose actual password diverged (factory reset, out-of-band change)
> re-acquires the last controller-pushed password at its next full
> provisioning; no cache ⇒ factory-default `ubnt` row (fresh salt, converges
> byte-stably after the delta applies). The jar-cited claims above are
> untouched.
>
> REST PATCH semantics are exact: absent `ssh_password` leaves intent unchanged,
> `""` stops managing it, and a nonempty value sets it. The Terraform
> `open-unifi_device.ssh_password` attribute is Optional and Sensitive; null or
> absent reconciles to the explicit API clear. Password changes remain
> bench/live-round owed, not live-proven.

## 11. Firmware-side acceptance gate — mcad (live-confirmed 2026-09-16)

The device does not blindly apply the `system_cfg` it receives: the inform-reporting
daemon `mcad` (`/usr/bin/mcad`, U7PG2 fw 6.8.2.15592) runs a VALIDATION GATE
before promoting the file (reverse-engineered in Ghidra; full record:
docs/AP-FIRMWARE-APPLY-PATH.md).

* Response dispatch (`ace_reporter.reporter_handle_response_json`, 0x00414acc):
  `mgmt_cfg` is written RAW to `/tmp/setmgmt.cfg` and parsed for
  `stun_url`/`mgmt_url`/`authkey`/`cfgversion` (echoed back) — **no validation**.
  `blocked_sta` is written raw and applied via `syswrapper_impl("apply-blocked-sta")`.
* `system_cfg` goes through a VALIDATED write (0x0040aaa8 → 0x0040a97c →
  0x0040a924): content is staged to `/tmp/system.cfg.tmp`, parsed with the external
  `libubnt parse()`, and accepted ONLY if the parsed tree contains ALL of
  * `users.1.status`
  * `netconf.1.status`
  * `sshd.status`
  On success: rename to `/tmp/system.cfg`, mcad logs `[setparam] applying new
  system.cfg` and calls `syswrapper_impl("apply-config", "/tmp/system.cfg")`.
  On ANY failure: the tmp file is unlinked, mcad logs `[apply-config] Unable to
  write system.cfg or its contents are invalid.`, dumps the whole response to
  `/etc/persistent/bad-response.json` (re-serialized pretty JSON — not the
  original bytes), and **apply-config never runs**.

⇒ Generator contract: every emitted `system_cfg` must contain `users.1.status`,
`netconf.1.status` and `sshd.status`. In particular `netconf.1` must ALWAYS exist
with its `status` row — the "omit mgmt netconf rows" shortcut is a guaranteed
firmware rejection behind a misleading "contents are invalid" log line.
(Live-observed 2026-09-16: every generated `system_cfg` push was rejected with
exactly that log until `netconf.1.status` was emitted; `mgmt_cfg` pushes applied
throughout because that path is unvalidated.)

## 12. Known deviations from the real builder (accepted 2026-09-16; extended by the 2026-09-17 night pass)

A full javap↔generator diff was performed against the real builder bytecode.
All per-object `.status` rows the real builder emits are present in ours (the
earlier suspicion of missing `radio.<n>.status`/`aaa.<n>.status`/
`wireless.<n>.status` rows is NOT supported by the bytecode). The head section
order (`# unifi` → `# system` → `# users`), the unifi pair order, `unifi.idp`
and `unifi.cfgcap_info` match the bytecode (int.txt:17208-17221,
String.txt:1851-1930, int.txt:16600-16630). Remaining accepted deviations:

| deviation | real builder | ours | rationale |
|---|---|---|---|
| `system.timezone`/`locale.timezone` | both rows skipped when the site locale is absent | always emitted with the default tz | parse() tolerates both shapes; real site configs carry a locale; not a mcad gate key |
| `bridge.status` | `disabled` when the bridge list is empty | always `enabled` | we always emit at least br0, so the real writer would emit enabled too |
| `radio.<n>.mode` | `managed` iff `create_vport`, else `master` | literal `master` | AP VAPs are masters in every default site shape |
| `aaa.<n>.verbose` | `4` when debug logging, else `2` | literal `2` | matches the non-debug default |
| `wireless.<n>.parent` | `wlan.getString("parent", flag?"wifi0":"eth1")` | radio-table `name` | real reads the Wlan bean's stored parent (same value on this hardware); the wifi0/eth1 fallback never applies for AP WLANs |
| `unifi.version` value | controller version string | `0.1.0-dev` placeholder | controller identity question, tracked separately |
| `unifi.idp` | jar default **enabled** (`Setting.is("unifi_idp_enabled", true)`, String.txt:1899-1902): emits `unifi.idp=enabled` plus `unifi.mcip=239.254.127.63` and `unifi.key=<mgmt x_mgmt_key>` rows | `unifi.idp=disabled`; no `unifi.mcip`/`unifi.key` rows | deliberate — open-unifi has no IDP feature; the AP-side validator ignores `unifi.*` rows |
| `unifi.cfgcap_info` value | version-derived bitmask (≤2.x→0x0, 3.0-3.2→0x3, 3.3+→0x7; int.txt:5332-5387) | literal `0x7` | running the algorithm on our `0.1.0-dev` placeholder would emit `0x0` and zero the AP plugin layer's capability gating (ubntconf `get_uint32` default 0); `0x7` is what every controller this firmware has paired with emits |
| `# mgmt` ledbar block | emitted headerless between `# users` and `# wlans` (String.txt:2566-2745) | **implemented row-for-row (2026-09-19 ledbar lane)** — internal/server/systemcfg/ledbar.go: the supportLedBar guard, the enabled computation (`!disabled && (led_override=="on" || =="default" && led_enabled site default)`), status+persistent always / brightness+active+color rows only when enabled, the truncating `(255*b)/100` brightness row, and the `Color.decode` fallback chain, all per the verbatim javap citation packet embedded in WORKER-BRIEF-ledbar.md | residual un-byte-verified pieces, all recorded in the lane report: (1) the `ledbar.status` mapper body (String.txt:2612 `super:(Z)Ljava/lang/String;`) is outside the packet — the emitted `enabled`/`disabled` values are corroborated by config_int.txt:5623-5626; (2) `java.lang.Integer.decode` is ported, not wrapped (non-ASCII Unicode digits fall back to `#0000ff` where the JDK would parse them); (3) `supportLedBar()` == `hasHardwareCapability(2)` (config_Device.txt:7935-7943) — the capability bit's record source is not carried by the packet, so the model set `{U7PG2}` is the in-repo device-class decision. Live-proof obligations stand: the block's on-wire bytes in a captured full provisioning response, and real LED state changes per override on the bench AP |
| dhcpc guest `ip_only` rows, `system.analytics.status`, `system.resetbtn`, `system.monitor.memory.threshold`, `aaa.<n>.radius.macacl.emptypassword`/`.format`, `wireless.<n>.mgmt_rate`/`bcast.enhance` | condition-gated | omitted at defaults | feature-gated rows that do not affect VAP bring-up; add when the corresponding admin features exist |
| `vlan.<n>.status` per-row | only in the `intsuper` bean; ABSENT on the AP `int` path | correctly absent | javap: `int extends String` inherits String's vlan writer (no per-row status); intsuper's extra row is not the AP path |
| hidden mesh/vwire/vport synthetic vaps | per-radio synth in the collector (int.txt:L12629, §2.1): `vport-<serial>` uplink vap when create_vport (⇒ `ath<N>`, `radio.<n>.mode=managed`); per-radio **mesh vap** when `supportVwire() && site connectivity enabled && radio vwire_enabled && supportMeshv3()` (⇒ `vwire<N>`, `usage=downlink`); `vwire-<serial>` peer vap only when the device `vwire_table` has rows for the band with non-empty `wds_peers` | never — planVaps emits vaps only for site WLANs (internal/wireless/plan.go:159-198); a radio with no WLAN emits no vap rows | deliberate — open-unifi has no mesh/wireless-uplink feature; our renders are byte-faithful to the real builder's vwire-disabled site shape (connectivity `enabled=false` ⇒ zero synthetics on the real path too). Consequence: WLAN-count changes alter the real builder's bridge ports just as they alter ours — see §2.1 and WLAN-ACCEPTANCE-6.8.2.15592.md §Bridge-apply verdict |
| `mgmt.is_default` | never emitted (no mgmt writer in config_String/int; `is_default` exists only in device-state classes) | **removed 2026-09-19** — the pre-fix factory-echo block emitted `mgmt.is_default=true` | live-proven hazard: the fw 6.8.2 preinit boot guard (`/lib/preinit/99_21_ubnt_ubntconf` `do_ubntconf`) replaces the MTD-restored blob text with the factory template when it contains `mgmt.is_default=true` ⇒ every reboot of a provisioned AP factory-reset the WLAN text while mgmt/authkey survived via the tar part (WLAN-ACCEPTANCE A2; AP-FIRMWARE-APPLY-PATH.md §6.5). Absence is the real shape |
| `mgmt.discovery.status`/`mgmt.flavor`/`dhcpd.*`/`httpd.status`/`ebtables.*` factory-echo rows | never emitted | echoed verbatim from the factory baseline (2026-09-16 zero-parsed-diff choice) | deleting unmanaged rows on full-config replacement had unknown plugin effects; the rows are inert at boot (the preinit guard consumes only `mgmt.is_default`); kept deliberately — see render.go |
| `aaa.<n>.radius.acct.<i>.ip/.port/.secret` rows | emitted per radiusprofile accounting server (port 1813) when `accounting_enabled` | **implemented (2026-09-19 acct lane)**: `accounting_enabled` + `acct_servers` on the inline profile (admin API validated: ≤4 entries, non-empty IPs, port 0→1813, profile-level `radius_secret` on every row); renderer emits `radius.acct.<i>.ip/.port/.secret` per server by array position, auth-row slot semantics mirrored; accounting off renders byte-identically to no accounting fields (renderer goldens + drift-hash rule pin it) | resolved as the radius lane's omission note prescribed: the accounting feature and these rows landed together (2026-09-19 acct lane); the interim/das companions follow row 1014 |
| `aaa.<n>.radius.das.*`/`radius.dad.*`/`interim_update.*` rows | gated on `radius_das_enabled` (+ accounting) and `interim_update_enabled` | **implemented (2026-09-19 acct lane + same-day das/dad flip)**: `interim_update.*` — `accounting_enabled` + `interim_update_enabled` → `interim_update.status=enabled`, `interim_update.interval=3600` (jar default). das/dad — under `accounting_enabled` + `radius_das_enabled` + the device fw_caps 0x100000 bit (hasCapability(1048576), int 1500-1539): the dad block (dad.status=enabled, dad.port=3799) once per device render (int 197-228), das.status=enabled + das.port=3800+n + dad.status=enabled per emitted aaa index (the jar re-emits dad.status in the das block — the duplicate is byte-exact, int 234-299), and the client rows from the acct server beans' own `ip` fields: das.client/das.secret once per index (int 527-604), dad.client.<i>.cidr=`<ip>`/32 + .secret per server slot (int 606-736). The admin API accepts the knob behind a requires-accounting gate; WlanListHash joins it under the same gate (the device-capability arm is envelope-external — recorded as a bounded residual on the hash) | the acct lane's open jar-recovery obligation is closed: the `<ip>` is the acct server bean's own admin-configured field (int offsets 564-736), so no value was ever invented; hotspot2conf_enabled shares the jar gate (int 1500-1539) but is unmodeled |
| `aaa.<n>.radius_acct_send_keyid.status`/`aaa.<n>.filter_id` | gated on Uid device classes (IoT/wifi) + `radius_filter_id_enabled` + `supportsRadiusFilter` | omitted (2026-09-19 radius lane; rationale re-confirmed 2026-09-19 acct lane — the gate needs Uid device classes, which U7PG2 cannot report, so no accounting-side work reaches these rows) | no Uid/IoT device classes in the model set; not reachable for U7PG2 |
| `radio.<n>.channel`/`txpower` when admin intent is set | always the radio_table echo (no admin storage recovered for U7PG2; confirmed by the 2026-09-19 txpower packet's pool-ref sweep — §9) | admin-owned `Extra["radio_intent"]` overlay wins (2026-09-19, §3.2/§8.1) | the feature this lane exists for: admin-saved radio settings must survive inform echoes and reach the device. No intent set ⇒ byte-identical echo render (pinned by tests); `txpower_mode` stays a pure echo — no controller-side writer for it exists in the config classes (txpower packet: reads int.txt 5687-5696 with default "auto", row emission int.txt 5942-5958, pool-ref sweep; resolved-as-echo §9) |

## 13. Addendum — `sshd.auth.key.<n>` rows and `sshd.auth.passwd=disabled` (2026-09-20 sshd-auth lane)

The `sshd` rows carried by the classic builder (config_String.java §309-337:
`sshd.status`, `sshd.auth.passwd`, `sshd.1.status`, `sshd.1.ifname`) until now
left `/etc/dropbear/authorized_keys` unpopulated — and the firmware REGENERATES
that file (together with users/sshd state) from persisted cfg rows on every
boot/apply (docs/AP-FIRMWARE-APPLY-PATH.md:192-209; live-confirmed wipe
docs/WLAN-ACCEPTANCE-6.8.2.15592.md:427-432), so a manually planted key was
wiped at the next boot. This addendum pins the authorized-key row family and
the password-auth knob the renderer now emits from two new site facts.

### 13.1 The `sshd.auth.key.<n>.*` row family (open-unifi extension)

Row names and the per-key index come from the U7PG2 firmware string cluster
(ubntbox, fw BZ.6.8.2.15592, 0x0063bd40-0x0063be80):
`"sshd.auth.key.%d.status"`, `"sshd.auth.key.%d.type"`,
`"sshd.auth.key.%d.comment"`, the default type `"ssh-rsa"`, and the bare
`".value"` suffix at 0x0064ec8c. The key line itself is written with format
`"%s %s %s\n"` (type, value, comment) to `/etc/dropbear/authorized_keys`
@0x0063f19c. The jar's per-key format strings (com.ubnt.service.config.String,
String.txt:2849-2911) fix the EMITTED ROW ORDER:
`sshd.auth.key.<n>.status=enabled`, `.value=<base64>`, `.type=<token>`,
`.comment=<comment>` — the comment row only when a comment exists (the
three-field line writer). Keys are 1-based, in site-fact slice order, no
dedup; zero keys emit zero rows (byte-identical to the pre-feature render).
The controller-side value is `systemcfg.ParsePublicKey` (fail-closed: exactly
2 or 3 fields, type `^(ssh|ecdsa)-[a-z0-9-]+$`, standard-base64 value that
must carry a structurally valid RFC 4253 §6.6 wire blob beginning with its
own type name and parsing as clean length-prefixed fields — a structure
check, NOT cryptographic validation) fed
from the persisted site-settings record — a new site fact, never
device-informable (site-facts definition, CONTEXT.md). The
`--device-ssh-key` flag / `$OPEN_UNIFI_DEVICE_SSH_KEY` env fallback is the
first-boot seed only; the record is the source afterwards (§13.3).

### 13.2 `sshd.auth.passwd=disabled` — the password-disable knob is REMOVED (fw defect)

The password-disable site fact NO LONGER EXISTS: the record field
(`ap_ssh_disable_password`), the `--ap-ssh-disable-password` first-boot
seed flag, the admin API field/view, and the Terraform attribute were
removed outright the same day the 2026-09-22 root-cause round byte-caught
why its row is lethal — no supported posture sets it safely on the only
target firmware. The renderer now emits `sshd.auth.passwd=enabled`
unconditionally (byte-identical to the old knob-off arm); a stale client
PUT still carrying `ap_ssh_disable_password` gets the strict-decoder
unknown-field 400 (pinned in the adminapi and provider composition
tests); old on-disk records carrying the field still load (every record
decoder is lenient). Firmware semantics of the row the knob used to
render (ubntbox dropbear respawn builder): the builder assembles
`"null::respawn:%s -F %s%s%s%s"` and appends the `"-s"` flag (disable
remote password logins) exactly when `sshd.auth.passwd` is disabled; port
comes from `sshd.%d.port` (`" -p %d"`) and the host keys are
`-r /var/run/dropbear_rsa_host_key` / `-r /var/run/dropbear_ed25519_host_key`.
LIVE-CAUGHT DEFECT (2026-09-22 root-cause round,
WLAN-ACCEPTANCE-6.8.2.15592.md §2026-09-22): on fw 6.8.2.15592 the
disabled branch's slot packing is BROKEN — the `-s` string is GLUED onto
the port argument. procd's live respawn line, caught in RAM-backed
`/var/log/messages`:
`/usr/sbin/dropbear -F -r /var/run/dropbear_rsa_host_key -p br0:22-s`
(the disabled line also drops the ed25519 `-r`). dropbear then logs
`Failed listening on '22-s': Error resolving: Unrecognized service` and
`Early exit: No listening ports available`, exits 256, and procd
respawns it into the same death (dropbear's own 60 s sleep backoff hides
the loop from cadence probes) — no listener, ever. The enabled branch
renders correct (empty `-s` slot — the double-space byte form), so the
defect is the disabled branch's adjacent `%s%s` slots with no separator
before `-s`; the SAME broken line is built by BOTH assembly paths
(apply-time and boot-rebuild — the row persists across reboot and the
fresh boot reproduces the outage, so reboot is NOT a recovery). History:
the 2026-09-21 round's `disabled` push settled and the listener never
returned; the outage and the controller-channel recovery are recorded in
§13.3, and the root cause was byte-caught by the 2026-09-22 round.

REMAINING EXPOSURE (sharp edge): the admin `config.system_cfg.<idx>`
passthrough rows render AFTER the site-fact sshd rows, so an admin can
still inject a literal `sshd.auth.passwd=disabled` row through the
passthrough — same fw defect, same outage. The removal closed the named
knob, not the arbitrary-row escape hatch (a conflicting admin-supplied
row's duplicate-resolution on the device — `sshd.auth.key` is an indexed
family, sorted-key row semantics — is unvalidated). Recovery needs no
SSH in that case either: an effective admin device save re-provisions
the record on the next inform (the controller channel), re-rendering the
sshd rows.

### 13.3 Live-validation status (apply-validated keys; REMOVED knob)

Both row families are FIRMWARE-DERIVED from the ubntbox evidence above.
Live-bench status after the 2026-09-21 site-settings round
(WLAN-ACCEPTANCE-6.8.2.15592.md §2026-09-21): the KEY rows are
APPLY-VALIDATED on the bench U7PG2 — a full provisioning carrying
`sshd.auth.key.1.*` settled byte-identically (applied sha `11cb0472…`),
the device rebuilt `/etc/dropbear/authorized_keys` FROM the rows, and a
BatchMode key login worked — but BOOT-REBUILD SURVIVAL is still OWED
(the round applied, it did not reboot; the pre-lane evidence is that
boot wipes manually-installed keys, so the row-driven boot path is
untested). The DISABLE knob is GONE, not merely gated: the 2026-09-22
root-cause round (WLAN-ACCEPTANCE-6.8.2.15592.md §2026-09-22) proved the
row's fw-side respawn line is broken at the source (`-p br0:22-s`,
§13.2) — the knob kills SSH ENTIRELY (password AND key lanes RST-refused
at apply AND after a fresh boot: branch C of the reboot discriminator, no
OPEN flicker, dropbear exit-256 respawn loop with 60 s backoff), so it
was removed from every writer outright (§13.2). Reboot was never a
recovery, and row-key boot survival was UNREACHABLE through the knob —
no branch of the discriminator could test it. The LIVE-PROVISIONING
GATE therefore STAYS for the sshd fact that remains, with live evidence
it is right to refuse it:
the adoption engine's fail-closed U7PG2/6.8.2.15592 choke point also rejects
any full provisioning whose site facts carry key rows, lifted by the same
`--allow-gated-live-wlan` opt-in (the engine
reads the distilled sshd scalar LIVE at gate time — `Deps.SSHSiteFacts
func() (keyRows int)`, sourced from the persisted record, not frozen
at construction). Coverage note: the gate's model/firmware predicate
trusts the device-reported values, absorbed verbatim from the inform body
under record absorption — a device naming another model (or another
firmware) leaves the gate inert for itself. The gate is bench-safety for
the controller's own emissions to the U7PG2/6.8.2.15592 lane, NOT a
device-trust boundary.

Known residual (recorded; deliberately not yet fixed): the gate read
(`Deps.SSHSiteFacts`) and the render read of the site-settings record are
two independent live reads within one decision. A site-settings save whose
settings-mutex acquisition lands in the microsecond window between the two
reads can emit ONE ungated full provisioning of the just-saved sshd rows
(the gate read the old facts, the render read the new). The escape is
one-shot and self-corrects at the next inform: the mint sweep's per-MAC
write is ordered after the escape's cycle, so the device's next inform is
guaranteed to mismatch and gate. The recorded remedy (not applied until
the owed live-bench round): re-derive the gate's sshd half render-side
inside `renderSystemCfg` under its own single facts read — the same
defense-in-depth shape as the country-code re-check.

Delivery semantics: site facts render at EMISSION; they reach an adopted
device at ADOPTION or the NEXT CFGVERSION MINT (a site-settings save, an
effective admin device save, a WLAN-change, a blocked-sta change, or the
watchdog path). The site-settings path is REAL end-to-end: a save (admin
API `PUT /api/v1/site-settings` or the Terraform `open-unifi_site_settings`
resource) applies the persisted record and — on effective change — mints
`cfgversion` across every device record carrying a cfgversion intent;
each device's next inform then full-provisions carrying the new sshd
rows (pinned E2E — save → mint → inform → `setparam` — in
internal/server/lifecycle_test.go). The record is the source of the three
device-intent facts; the cmd flags are first-boot seeds only, ignored
whenever the record file exists. A no-change save mints nothing — a
settled device with an unchanged cfgversion noop. And the sshd rows are
NOT inform-observable (the vap_table/echo reports carry no sshd keys), so
the cfgversion echo after a full provisioning is the ONLY delivery
confirmation a bench round can observe; the rows' persistence surfaces at
the next boot rebuild.

(End; see PROTOCOL-mgmt.md §3 for the surrounding `system_cfg` order and §6/§7 of
PROTOCOL-mgmt.md for how system_cfg reaches the device.)
