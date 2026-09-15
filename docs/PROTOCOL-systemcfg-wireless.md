# PROTOCOL-systemcfg-wireless — `radio.*` / `aaa.*` / `wireless.*` schema for a classic Atheros AP (U7PG2)

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
| `channel` | 0 = auto | radio_table `channel` |
| `backup_channel` | 0 | radio_table `backup_channel` |
| `ieee_mode` | `11n` | `_int.cfr_renamed_1(isNg, chanWidth)` §737-743 = `"11n" + (isNg ? "g" : "a") + "ht" + <width>`; width source `cfr_renamed_2(radio, country)` — UNRESOLVED (§9) |
| `mode` | master | `managed` only when a vport wds-aplink is provisioned on this radio (`create_vport`, §1310) |
| `rate.auto` | enabled | literal |
| `rate.mcs` | auto | `\u00f4\u00f40000 = "auto"` (int §151) |
| `rfscan` | disabled | radio_table `spectrum_enabled` |
| `bcmc_l2_filter.status` | enabled | site/X `config.mcast_filter_enabled` default true |
| `bgscan.status` | disabled | literal |
| `antenna.gain` | 0 | `builtin_antenna ? builtin_ant_gain : antenna_gain` (default 6 absent, §510) |
| `antenna` | -1 | radio_table `antenna_id` (default -1) |
| `txpower_mode` | auto | radio_table `tx_power_mode` (default `\u00f4\u00f40000` = "auto") |
| `txpower` | auto | radio_table `tx_power` |
| `hard_noisefloor.*` | `status=disabled` | when `sens_level_enabled` + advanced: `enabled, max_sens=-40, minrssi.value=…, minrssi_backoff=0` (§519-525) |
| `stamgr.<n4>.*` | (separate key, radio-index) | only when `advanced_feature_enabled` + any of min-rssi/load-balance: `status=true, radio=ng, minrssi.status, minrssi.rssi, loadbalance.status, loadbalance.maxsta` (§527-531) |

Per-vap companion (only when `vapIdxOnRadio > 0`, int §536-542):
```
radio.<n4>.virtual.<vapIdx>.devname=athX
radio.<n4>.virtual.<vapIdx>.status=enabled
```

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

### 4.3 WPA-PSK / WPA-EAP branch (int §595-612)
Fixed block (§597, one `C.o00000` call with pairs → each pair becomes one row):
```
aaa.<n>.br.devname=…        aaa.<n>.devname=ath<X>       aaa.<n>.driver=madwifi
aaa.<n>.ssid=<name>         aaa.<n>.status=enabled        (only is_wds_uplink → "disabled")
aaa.<n>.verbose=2                                        (4 on debug builds, R.\u00d8\u00d2O000())
aaa.<n>.wpa=<int>                                        WpaMode.getMode(): AUTO=3, WPA1=1, WPA2=2 (enum javap)
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

**WPA-Enterprise (`wpaeap` / `osen`)** — int §775-789, RADIUS helper §791-840:
```
aaa.<n>.wpa.key.1.mgmt=WPA-EAP               (OSEN → "OSEN")
aaa.<n>.wpa.psk=<x_passphrase>               (same fallback "letmeinnow"!) + auth_cache=enabled|disabled
aaa.<n>.radius.auth.<i>.ip/.port=1812/.secret=<x_secret>     i=1..4, skip empty ip (servers from wlanConf auth_servers, via radiusprofile copyAttrsIfPresent int §1401-1405)
aaa.<n>.radius.acct.<i>.ip/.port=1813/.secret=<x_secret>     only if accounting_enabled
aaa.<n>.radius.das.status=enabled/.das.port=<3800+n>/radius.dad.status=enabled   (radius_das_enabled + accounting)
aaa.<n>.radius.dad.client.<i>.cidr=<ip>/32 + .secret=<x_secret>
aaa.<n>.radius.das.client=<ip> / .das.secret=<x_secret>
aaa.<n>.interim_update.status=enabled / .interval=<3600>     (interim_update_enabled)
aaa.<n>.dynamic_vlan=0|1|2                    vlan_wlan_mode disabled/optional/required → 0/1/2 (default 0)
aaa.<n>.radius_acct_send_keyid.status=enabled  (Uid IoT + psk-radius non-disabled)
aaa.<n>.filter_id=UID_WIFI                    (Uid wifi + radius_filter_id_enabled + supportsRadiusFilter)
```
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
| `# netconf` | `netconf.<l>` for each bridge iface: `devname=br0.<vid>, ip=0.0.0.0, autoip.status=disabled, netmask=<unset>, promisc=enabled, up=enabled` | config_String §551-593 |
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
radio.1.ieee_mode=11nght<UNRESOLVED>         (chanWidth helper; commonly "20" default)
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
# radio.2.* = same field set; phyname=rai0, ieee_mode=11naht<UNRESOLVED>, antenna values per na row

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
# (No `radio.<n>.virtual.*` lines here because vapIdxOnRadio == 0 on each radio.)

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
netconf.<k>.devname=br0.42
netconf.<k>.ip=0.0.0.0
netconf.<k>.autoip.status=disabled
netconf.<k>.netmask=<null-filtered>
netconf.<k>.promisc=enabled
netconf.<k>.up=enabled

# dhcpc (rows for GUEST vlans only; none here since guest wlan disabled; mgmt row only when device IP is DHCP)
dhcpc.status=enabled

# (adjacent sections, out of excerpt scope: "# bandsteering", "# airtime fairness",
#  "# stamgr", "# qos", "# mac acl", "# mesh", "# connectivity" — order per
#  PROTOCOL-mgmt.md §3.)
```

## 8. Admin-API field → system_cfg mapping (Go contract)

| our Wlan field | WlanConf source | drives |
|---|---|---|
| `name` | `name` (same value used for `ssid`) | `wireless.<n>.name`/`ssid`, `aaa.<n>.ssid` |
| `security=open` | `security=open` | NO `aaa.<n>.wpa.*`; `wireless.<n>.authmode=0`, `security=none`; `aaa.<n>.status` = enabled iff device `wifi_caps` bit `0x2000` (`supportOpenHostapd`, Device.java §1275 & §1247) — **device-record dependent; check per adopter** |
| `security=wpa-p` | `security=wpapsk` (wpa_mode AUTO→2, wpa_enc AUTO→CCMP) | `aaa.<n>.wpa=2`, `.eapol_version=2`, `.wpa.key.1.mgmt=WPA-PSK`, `.wpa.psk=<passphrase>` (plaintext), `.wpa.1.pairwise=CCMP`, `.pmf.cipher=AES-128-CMAC`, `.wpa.group_rekey=3600`, `wireless.<n>.authmode=1`, `security=none` |
| `security=wpa-eap` | `security=wpaeap` | `wpa.key.1.mgmt=WPA-EAP` + `wpa.psk` (⚠ same fallback "letmeinnow" if not set) + `radius.auth.<i>.{ip,port,secret}` + `dynamic_vlan=0` + `auth_cache=enabled`; acct servers need the RADIUS profile (int §1401-1405 copyAttrsIfPresent) |
| `passphrase` | `x_passphrase` (fallback literal `"letmeinnow"`) | `aaa.<n>.wpa.psk` verbatim — **never hashed/obfuscated on this writer** |
| `vlan=<vid>` | `vlan` (or bound `networkconf_id`) | new `br0.<vid>`: `# vlan` row(s), `# bridge` row + `port.*.devname=ath…`, `# netconf` row, `aaa.<n>.br.devname=br0.<vid>`; guard `vid != 1` (else br-trunk). For EAP: `aaa.<n>.dynamic_vlan=1|2` + DAS/DAD rows (optional) |
| `vlan` absent/0 | – | `aaa.<n>.br.devname=br0`; no `# vlan`/bridge additions; (device mgmt-network overridden → joins br-trunk, §6) |
| `enabled=false` | `enabled` | **entire WLAN omitted** (F.super return null ⇒ no vap, no bridge membership, no dhcpc row) |
| `enabled=true` | `enabled` | vap + all rows above with `wireless.<n>.status=enabled` (literal) |
| hidden | `hide_ssid` | `aaa.<n>.hide_ssid` AND `wireless.<n>.hide_ssid` |
| guest | `is_guest` | `aaa.<n>.is_guest=true`, `wireless.<n>.is_guest=true`, `usage=guest`, `l2_isolation` defaults to enabled, plus `dhcpc.<m> ip_only=true devname=br0.<vid>` for its bridge |
| `wlan_band` | `wlan_band` (2g/5g/both) | how many vaps the WLAN gets (one per band on the device) |
| schedule | `schedule_*`, `schedule_enabled` | `wireless.<n>.schedule_enabled` + `schedule_<off|on>[.<i>]=<from>-<to>` rows |

Defaults the Go builder must reproduce (`WlanConf.java` getters, cited):
`hide_ssid=false`, `b_supported=false` ⇒ `pureg=1`, `group_rekey=3600`,
`dtim=3`, `wpa_enc=auto` ⇒ `CCMP`, `wpa_mode=auto` ⇒ `wpa=2 / eapol 2`,
`x_passphrase` fallback `"letmeinnow"`, `auth_cache=true` (EAP),
`vlan_wlan_mode=disabled` ⇒ `dynamic_vlan=0`.

## 9. UNRESOLVED / explicitly searched & not found

- `radio.<n>.ieee_mode` `<ht>` value: source = `com.ubnt.service.devmgr.c
  \u00f6\u00f60000.cfr_renamed_2(radio, countrycode)` (int §514, width check
  `n2 != 20` §515). Searched device-manager decompiles present in the lane
  (`devmgr/ooOo`, `devmgr/privatesuper`, `devmgr/command/general/public`) — no
  such resolver body found; the class `com/ubnt/service/devmgr/c.class` was not
  decompiled in this pass. Go can emit `"20"`-suffixed form for default sites;
  verify against a live device cfg dump before shipping.
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

(End; see PROTOCOL-mgmt.md §3 for the surrounding `system_cfg` order and §6/§7 of
PROTOCOL-mgmt.md for how system_cfg reaches the device.)
