# UniFi "inform" protocol — ground truth extracted from ace.jar (v7.x controller deb)

Source of truth: bytecode decompilation of `tmpwork/data/usr/lib/unifi/lib/ace.jar`
(classes verified: `com.ubnt.net.InformServlet`, `InformServlet$_O0`, `com.super.A.OOoO`,
`com.ubnt.net.interface|J` (default-key providers), `com.ubnt.service.devmgr.voidsuper`,
`com.super.A.A.O0oO/G/D` (UDP discovery), `com.ubnt.service.config.*`).
All offsets/int endianness below were read out of real bytecode, not guessed.

## 1. Inform packet wire format

HTTP POST to `http://<controller>:8080/inform` (Content-Type `application/x-binary`),
body:

```
offset  size  field
0       4     magic  (big-endian uint32) = 0x544E4255  == ASCII "TNBU"
4       4     packet version (BE uint32). Device requests currently version 0.
8       6     device MAC (raw 6 bytes)
14      2     flags (BE uint16): 0x01 encrypted-CBC, 0x02 zlib, 0x04 snappy, 0x08 AES-GCM
16      16    IV / nonce
32      4     data version (BE uint32); request must be 1
36      4     payload length (BE uint32); for GCM this INCLUDES the trailing 16-byte tag
40      n     payload (see below)
```

- Max accepted body 10 MB (0xA00000); short bodies rejected.
- `dataVersion != 1` → error "Data version %d is not supported".
- Payload length must be `len(body) >= 40 + dataLen`.

Payload processing (request):
1. If flag 0x08: AES-GCM decrypt with key, nonce=16-byte IV field, AAD = the entire
   40-byte header (with payload-length field as parsed, i.e. including tag size),
   tag = last 16 bytes of payload (128-bit tag, appended). Java: AES/GCM/NoPadding.
2. Else if flag 0x01 (and not GCM): AES-CBC. Bytecode attempts PKCS5 paddingBottom first
   and falls back to AES/CBC/NoPadding on BadPaddingException (lenient legacy support).
3. If flag 0x04: zlib-inflate (wallet flag 0x02 = snappy uncompress) — order:
   zlib if 0x02 set, snappy if 0x04 set. (Device gen2 sends zlib.)
4. Result is JSON (see §3).

Response construction (controller → device):
- If the request was *encrypted*, the response MUST be encrypted (same header plumbing):
  reuse the request header shape, generate a NEW random 16-byte IV,
  `flags = 0x0009` (GCM) when device signaled GCM capability or request was GCM, else
  `flags = 0x0001` (CBC). GCM response: AAD = 40-byte header, tag appended,
  payloadLen = ciphertext+tag length. CBC response: payloadLen = ciphertext length.
- If the request was *plaintext JSON* (only allowed when device is in pre-adoption and
  "plain text inform" enabled — classic controllers reject it), respond with plain JSON
  serialized into the response body.
- JSON body keys for every response: at minimum `server_time_in_utc` (ms epoch, string).

## 2. Encryption keys

- Keys are stored/transported as 32-char lowercase hex strings (AES-128 key bytes).
- **Factory default key** (pre-adoption, all classic controllers):
  ```
  ba86f2bbe107c7c57eb5f2690775c712
  ```
  (= MD5("ubnt"), confirmed: `com.ubnt.net.interface#key(mac)` returns this literal).
  The GCM/CBC cipher for the first inform uses this key.
- Response uses the SAME key the device used (controller echoes request-perceived key).
- Post-adoption the controller generates a NEW per-device key:
  `x_authkey` = 32 random hex chars from alphabet `0123456789abcdef`
  (`C.o00000("0123456789abcdef", 32)`), stored `device.x_authkey` and pushed to the
  device inside `mgmt_cfg` (`unifi.x_authkey=...`), after which the device encrypts
  with it (and includes an `x_aes_gcm` capability flag).
- Devices that keep using the default key after adoption are recorded as
  `default:true` and put back into adoption.
- A device may have MULTIPLE valid keys (`device.authkeys` list); controller tries each
  until one decrypts. Include the default key in the list during adoption so we can
  decrypt the first packet.

## 3. JSON payloads (plaintext after decryption)

Request (device → controller), classic fields seen in `voidsuper`:

```json
{
  "_type": "info",               // also: heartbeat, alarms?, cmd-ack/setparam-ack etc.
  "_authkey": "<hex key in use>",
  "_devsiteid": "<site id, absent for factory device>",
  "mac": "24:xx:xx:xx:xx:xx",
  "model": "U7PG2",              // UAP-AC-Pro-Gen2
  "type": "uap",
  "version": "6.6.55",           // firmware
  "required_version": "...",     // device's notion of minimum controller version
  "architecture": "mips",
  "kernel_version": "3.5.0",
  "board_rev": 17,
  "manufacturer_id": 30,
  "serial": "F4xxxxxxxxx",
  "hash_id": "<32 hex>",         // unique-ish device identity
  "anon_id": "<32 hex>",         // analytics anion
  "ip": "10.0.0.23", "netmask": "...", "gateway": "...",
  "inform_url": "http://<ctrl>:8080/inform",
  "inform_ip": "<inform host as seen by device>",
  "_devextip": "public IP or 'ip_unknown'",
  "gateway_mac": "...", "internet": true,
  "uptime": 1234,
  "cfgversion": "<32 hex>",      // device's applied-config version
  "state": 1,                    // 1 = adopting, 0 = normal(connected); other states exist
  "x_aes_gcm": true,             // device supports AES-GCM
  "fingerprint": "aa:..",        // device ssh host key fingerprint (opt)
  "wlan-recalc": true,           // ask controller to recalc WLAN schedule
  "sys_stats": {"loadavg_1": "...", "mem_total": n, "mem_total_low": false, ...},
  "stat": {"user-num_sta": n, "user-rx_bytes": n, "user-tx_bytes": n, ...},
  "radio_table": [...], "vap_table": [...], "port_stats": [...]
}
```

Response (controller → device) is one of:

| response `"_type"` | when | keys |
|--------------------|------|------|
| (none) — HTTP 404 | device MAC not provisioned | – |
| (none) — HTTP 400/408 | decrypt/parse errors | – |
| `noop` | connected, nothing to do | `interval` (seconds to next inform) |
| `setparam` | config changed / adoption | `cfgversion`, `mgmt_cfg`, `system_cfg`, `blocked_sta` |
| `cmd` | one-shot tasks | `cmd` = adopt|reboot|restart|setdefault|upgrade|set-inform etc., plus cmd-specific fields |
| `heartbeat` | – | `interval` |

Adoption handshake (factory AP pointing at controller, verified paths):

1. AP POSTs first inform (default key, state 1). Controller has no device record →
   HTTP 404 is FINE for the AP (it keeps retrying).
2. Admin registers the MAC (UI/API/terraform) → device record with
   `state=1 (PENDING)`, `default` key accepted.
3. AP inform (state 1, default key) → controller responds `setparam` with:
   - `cfgversion` = new 16-hex random
   - `mgmt_cfg` = management config blob (see §5):
     contains `unifi.cfg_version`, `unifi.adopted=<id>`? `unifi.x_authkey=<hex>`
   - (response encrypted with default key)
4. AP applies mgmt config, now uses `x_authkey`, re-informs. If a second inform
   arrives still encrypted with the default key, regenerate `x_authkey` (16→32 char)
   and re-push (`[device authkey] send non-default authkey` path).
5. Next inform with new key + matching `cfgversion` → device considered CONNECTED
   (state 0). Response `noop` with `interval` (e.g. 15-60 s).
6. Subsequent informs w/ `cfgversion` mismatch → `setparam` + new
   `cfgversion` + `mgmt_cfg` + optionally `system_cfg` (full site config text for
   diag/cache; also sent as `system.config.system_cfg` entries inside mgmt_cfg).

Device state table (from `Device.getStateName` usage): 0? = connected,
1 = pending/adopting, 2 = adopted?, 4 = upgrading, 5 = provisioning,
8 = "adopt pending factory reset", 9 = ? (INFORM_ERROR); classic states include
FLASHING/UPGRADING/PROVISIONING/HEARTBEAT_MISSED/DISCONNECTED/ADOPTING/GETTING_STATUS/
INFORM_ERROR. Our store maps raw numbers; exact enum lives in Device class (TODO verify
tomorrow against device messages).

## 4. UDP 10001 discovery ("LiteStationQueryServer")

Packet: `[ver:1][cmd:1][dataLen:2 BE][TLV stream]`; TLV = `[type:1][len:2 BE][value]`.

Device announce (cmd 6 = 0x06) / challenge-resp (cmd 2); v2 announce (cmd 8) ignored;
"invoke sshd" hint sent BY CONTROLLER to device: bytes `02 0A 00 00`.
Controller announce response packet: ver/cmd built from `oooO(9, 2)` … important TLVs:

| type | value |
|------|-------|
| 1 | 6-byte MAC (local interfaces each, repeatable as type 2 = mac6+ip4) |
| 3 | firmware version string |
| 10 | uptime (u16) |
| 11 | hostname |
| 12 | platform / hardware id |
| 13/14 | essid / wmode |
| 16 | hex hash |
| 18 | seq (u16, anti-replay; drop if increased and <5s since last) |
| 19 | sender MAC |
| 21..26 | model, name, supported-bools |
| 27 | ssh username |
| 28 | ssh port (int) |
| 33..38 | site-id related strings |
| 39 | hash_id (32 hex) |
| 42 | UUID (two u64 BE) |
| 48/49 | bool, int |

For MVP: our controller listens on :10001, parses v0/v1/v2 announces, stores pending
device records (max_pending devices), optionally replies like O0oO does (mac+ip, 3=ver,
21/22/23 TLVs). Adoption primarily happens via SSH set-inform; discovery UI shows
candidates.

## 5. Config blobs (`mgmt_cfg` / `system_cfg`) — OPEN QUESTIONS

- `mgmt_cfg`: built per-device-type by `com.ubnt.service.config.nullsuper#forsuper(Device)`
  → dispatch to type-specific writer (`S` for generic APs, `R` UDM, `o0Oo` Cavium,
  `M`, returnsuper/OoOo for MediaTek/Espressif...). For classic APs the writer chain is
  `OoOo` (abstract) → `S` (empty overrides seen in CFR with feared renames — treat as
  unresolved). Content is a TEXT config in "unifi.*" key=value lines (device-side
  `/var/etc/persistent/cfg/mgmt` syntax), historically:
  ```
  unifi.cfg_version=<32 hex>
  unifi.x_authkey=<32 hex>
  unifi.<MANY OPTIONS>=...
  ```
  ⇒ **Lane A** must finish this trace from decompiles and write docs/PROTOCOL-mgmt.md.
- `system_cfg`: full AP system config text (`wireless.*`, `rmon.*`, …) built by
  `com/ubnt/service/config/int.class` (~"StringBuilder" lines seen) — same lane.
- `blocked_sta`: list of blocked client MACs (array of strings).

## 6. Go implementation contract (lanes write exactly these)

Package `internal/inform` (lane B):
```go
type Packet struct { Version uint32; MAC net.HardwareAddr; Flags uint16; IV [16]byte; DataVersion uint32; Payload []byte }
const Magic uint32 = 0x544E4255     // "TNBU"
const FlagEncCBC, FlagZlib, FlagSnappy, FlagGCM uint16 = 1, 2, 4, 8
func ParsePacket(body []byte) (*Packet, error)     // full validation incl. sizes
func (p *Packet) Serialize() ([]byte, error)
func DecryptPayload(p *Packet, key []byte) (json []byte, err error)  // CBC(+fallback)/GCM
func EncryptPayload(p *Packet, key []byte, json []byte) error        // fills Payload, Flags, IV
func DecodeKeyHex(s string) ([]byte, error)        // 32-char hex => 16 bytes
const DefaultKeyHex = "ba86f2bbe107c7c57eb5f2690775c712"
```

Package `internal/server` (lane C) — HTTP handler semantics:
- `POST /inform` parses body, tries device keys (default first for unknown MACs),
  dispatches via `internal/store` records, writes one of: 404 / 400 / encrypted JSON.
- UDP :10001 listener per §4 (declare+store pending announcers).
- Adoption FSM per §3; emits Prometheus events via `internal/metrics`.

Package `internal/store`: JSON-backed file store (interface below) — lane C may use
anything as long as `Get/mac` + `Put` + optimistic locking stays.
```go
type Device struct { MAC, Model, Firmware string; State int; Authkeys []string; SiteID string;
  IP, InformURL string; LastSeen int64; CfgVersion string; Tags []string; Warnings []string }
```

Package `internal/adminapi` (lane D): REST over JSON at `:8443`-style addr flag
`--listen-admin`:
```
GET    /api/v1/devices
POST   /api/v1/devices            {mac, name?, site_id?}  -> creates PENDING record (adopt)
DELETE /api/v1/devices/{mac}
GET    /api/v1/devices/{mac}      (state, last_seen, model, fw, metrics snapshot)
GET    /api/v1/pending            (discovery-found candidates)
POST   /api/v1/pending/{mac}/adopt
GET    /api/v1/config/healthz     -> 200 ok
Metrics at /metrics (promhttp).
```
Auth: optional `--admin-token <hex>`; when set require `Authorization: Bearer <token>`
with 401 otherwise. Terraform provider uses this.

Web UI (lane D): static page at `/`:
- list of devices & pending adopters,
- `Adopt` button → POST /pending/{mac}/adopt,
- textarea/dropdowns for: SSID name, passphrase, security (open/wpa-p/wpa-eap),
  VLAN id; save → POST /api/v1/config/wireless (adminapi shape).

Package `provider` (lane E, at provider/ dir + cmd/tfprovider):
resources `open-unifi_access_point` (adopt, by MAC + controller URL/token),
`open-unifi_wlan` (ssid, security, passphrase, vlan), data source `open-unifi_devices`.
Provider `Configure` accepts `url`, `token` (honest: token required unless server
started without --admin-token).

## 7. Whatever is still uncertain (carry-list)

- Exact `mgmt_cfg` text encoding (lane A resolves).
- `system_cfg` exact format and whether device threat-level influences provisioning.
- Device-side state enum numeric values & `cfgversion` semantics when mismatch (we
  handle: same → noop; different → setparam full shape).
- What happens on `two_phase_adopt` flows (applies only to older firmware; OUR flow
  targets 6.x which adopts in one phase).
- Discovery response packet exact TLVs needed for the AP to acquire inform URL from
  broadcast (O0oO builds it; not fully extracted) — lane A also should grab
  `oooO`/`H` builders while in the jar. till the device is wired we can rely on SSH
  set-inform; documented as tomorrow's onboarding step.
