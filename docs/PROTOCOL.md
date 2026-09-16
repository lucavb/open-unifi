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
3. If flag 0x02: zlib-inflate. If flag 0x04: snappy. **Classic controller DOES
   decompress flag 0x04** — the servlet's request chain runs
   java.util.zip.Inflater (`super([B)`) for 0x02 and then a snappy gate calling
   `org.xerial.snappy.Snappy.uncompress` (`Ò00000([B)`) for the next flag
   (tmpwork/javap/com__ubnt__net__InformServlet.txt:1693-1703; snappy helper at
   :2402-2421). "Does not support snappy" was an open-unifi limitation
   misattributed to the classic controller: open-unifi currently REJECTS 0x04
   payloads with an error (README Status & limitations); supporting snappy is
   still TODO in open-unifi.
4. Result is JSON (see §3).

Response construction (controller → device):
- If the request was *encrypted*, the response MUST be encrypted (same header plumbing):
  reuse the request header shape, generate a NEW random 16-byte IV, and set
  `flags = 0x0009` (GCM) iff the REQUEST itself carried flag 0x08, else `flags = 0x0001`
  (CBC). The device's advertised `x_aes_gcm` capability does NOT influence the response
  cipher — only the request's own flags do (PROTOCOL-mgmt.md §5: response GCM ⇔ request
  flags & 8; a CBC request that merely advertises `x_aes_gcm:true` gets a CBC response).
  dataVersion is echoed unchanged (= 1). GCM response: AAD = the RESPONSE's own
  40-byte header (the exact bytes transmitted on the wire), tag appended, payloadLen =
  ciphertext+tag length. CBC response: payloadLen = ciphertext length.
- Unencrypted informs — TNBU-framed packets without flags 0x01/0x08 (including zlib-only
  0x02) as well as unframed JSON bodies — are REJECTED with 400 "Plain text inform is
  not supported" unless the controller runs with `--allow-plaintext-inform` (mirrors the
  classic servlet's debug-build gate, PROTOCOL-mgmt.md §5). When allowed, the response
  is plain JSON. Open-unifi deviation from classic debug behavior: plaintext informs
  never initiate adoption and never rotate keys (PROTOCOL-mgmt.md §9).
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
  device inside `mgmt_cfg` (the `authkey=` line — exact 10-line blob in
  PROTOCOL-mgmt.md §2; the historical `unifi.x_authkey=` spelling is superseded),
  after which the device encrypts with it (and includes an `x_aes_gcm` capability
  flag).
- Devices that keep using the default key after adoption: the classic controller
  REJECTS the inform from a device in any state other than UNKNOWN(0) or
  INFORM_ERROR(9) — warn "dev[{}] used default key in {} state, reject it!" and
  return the error envelope; only then is it recorded as `default:true` (and the
  device put back into adoption) (tmpwork/javap/com__ubnt__service__devmgr__voidsuper.txt:8062-8115).
  Earlier revisions described "default-key inform ⇒ re-adopt" unconditionally; the
  unconditional re-adopt was an **open-unifi deviation**, not classic behavior —
  open-unifi is being aligned to the jar's state gate in this fix wave.
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
  "state": 1,                    // device-reported state; see §3 "state field" below.
                                 // NOTE: classic inform dispatcher does NOT copy `state`
                                 // out of the payload (voidsuper.txt:20660-20712),
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
   - `mgmt_cfg` ONLY (adoption push — PROTOCOL-mgmt.md §6.2 rows c/f): the 10-line
     blob of §2 (PROTOCOL-mgmt.md §2) with a fresh 16-hex `cfgversion=` line and
     `authkey=<new x_authkey>`
   - (response encrypted with default key)
4. AP applies mgmt config, now uses `x_authkey` (32 hex), re-informs. If a second
   inform arrives still encrypted with the default key, rotate `x_authkey` +
   cfgversion again and re-push (the "send non-default authkey" path,
   PROTOCOL-mgmt.md §6.2 row f).
5. Next inform with new key + matching `cfgversion` → device considered CONNECTED
   (classic `Device` enum state 1; open-unifi store state 3 = adopted). Response
   `noop` with `interval` (e.g. 15-60 s).
6. Subsequent informs w/ `cfgversion` mismatch → full-provisioning `setparam`:
   new `cfgversion` (16-hex) + `system_cfg` (full system config text —
   PROTOCOL-mgmt.md §3 / PROTOCOL-systemcfg-wireless.md) + `blocked_sta` + `mgmt_cfg`
   (always all four keys — PROTOCOL-mgmt.md §6.2 row d).

`state` field semantics — three distinct enums, do not conflate:

1. **Controller-side `Device` state enum** (classic, tmpwork/javap/com__ubnt__data__Device.txt:11897-11947,
   the `getStateName()` static-name table):
   0=`UNKNOWN`, 1=`CONNECTED`, 2=`PENDING`, 3=`FIRMWARE_MISMATCH`, 4=`UPGRADING`,
   5=`PROVISIONING`, 6=`HEARTBEAT_MISSED`, 7=`ADOPTING`, 8=`DELETING`,
   9=`INFORM_ERROR`, 10=`ADOPT_FAILED`, 11=`ISOLATED` (corroboration:
   `getState()==1` → "connected", tmpwork/javap/com__ubnt__service__devmgr__voidsuper.txt:14244-14248).
2. **open-unifi controller-side store lifecycle** (different numbering): 1=pending,
   2=adopting, 3=adopted, 4=lost.
3. **The inform payload's own `state` field**: the classic inform dispatcher does
   NOT copy it out of the payload into the device record (the payload-copy key
   arrays in tmpwork/javap/com__ubnt__service__devmgr__voidsuper.txt:20660-20712 —
   uptime/model/version/hostname/sshd_port/hash_id/anon_id/LTE/ubb/`default`/
   `locating` — contain no `state`).

## 4. UDP 10001 discovery ("LiteStationQueryServer")

Packet: `[ver:1][cmd:1][dataLen:2 BE][TLV stream]`; TLV = `[type:1][len:2 BE][value]`.

Device announce (cmd 6 = 0x06) / challenge-resp (cmd 2); v2 announce (cmd 8 = 8)
**is NOT ignored by the classic controller**: the parser's cmd-8 branch (packet
ver 2, cmd 8) first asks the `while()` discoverable gate — controller still in
setup mode (`supersuper.StringObject()`) OR the cached
`Setting "mgmt" → "discoverable"` is true (afterPropertiesSet reads it once,
default false) — then requires the source socket address to be a site-local
`InetSocketAddress`, and only then sends the cmd-9 reply packet to that address
(gate: tmpwork/javap/com__ubnt__net__K.txt:620-646; reply path:
tmpwork/javap/regen/O0oO_discovery_redump.txt:1462-1564; site-local check
`Ó00000(SocketAddress)`: tmpwork/javap/regen/O0oO_discovery_redump.txt:1232-1252;
full reply layout in docs/PROTOCOL-discovery.md §2.3/§2.4).
"cmd-8 ignored" was an open-unifi limitation (announce-only listener); replying is
still TODO in open-unifi.
"invoke sshd" hint sent BY CONTROLLER to device: bytes `02 0A 00 00`.
Controller announce response packet: ver/cmd built from `oooO(9, 2)` … important TLVs:

| type | value |
|------|-------|
| 1 | 6-byte MAC (local interfaces each, repeatable as type 2 = mac6+ip4) |
| 3 | firmware version string |
| 10 | uptime — 4-byte big-endian int via the shared `OOoO.class([B)` helper (O0oO_discovery_redump.txt TLV switch) |
| 11 | hostname |
| 12 | platform / hardware id |
| 13/14 | essid / wmode |
| 16 | hex hash |
| 18 | seq — 4-byte BE int, anti-replay: the jar drops a packet only when **(now − last < 5 s AND seq ≤ lastSeq)**; a higher seq within the 5 s window IS accepted (O0oO_discovery_redump.txt:862-928) |
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

## 5. Config blobs (`mgmt_cfg` / `system_cfg`) — RESOLVED

- `mgmt_cfg`: 10-line text blob (exact line order + the conditional `authkey=` rule):
  **PROTOCOL-mgmt.md §2** (bytecode-cited from the B-writer decompile). Historical
  `unifi.*`-prefixed spellings are superseded.
- `system_cfg`: full AP system config text — sections `# system`, `# unifi`, `# users`,
  the wireless compound (`# wlans (radio)`, `radio.<n>.*`, `aaa.<n>.*`,
  `wireless.<n>.*`, `# vlan`, `# bridge`, `# netconf`, `# dhcpc`), `# sshd`, `# misc`:
  **PROTOCOL-mgmt.md §3** for the frame and **PROTOCOL-systemcfg-wireless.md** for the
  complete wireless schema, worked example and Go mapping.
- `blocked_sta`: blocked client MACs (newline-joined string; empty when none).

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

Package `internal/store`: JSON-backed file store (internal/store/store.go is the
contract; in-memory impl exists for tests). Per-device read-modify-write goes through
`Update(mac, fn func(*Device) error) error` (per-MAC serialization; upserts when the
record is absent); `Get` returns a deep copy. `Device` fields as implemented: MAC
(canonical lowercase 12-hex string), Name, Model, Firmware, Serial, SiteID, State
(controller-side lifecycle: 1=pending, 2=adopting, 3=adopted, 4=lost), IP, InformURL,
LastSeen, FirstSeen, CfgVersion, AppliedCfg, Authkeys (assigned-key history, newest
last, capped at 2 — the factory default key is NEVER stored here), XAuthkey, AESGCM,
LastUps, Extra (inform-body passthrough; controller-owned `wlan_cfg_sha`/
`ssh_sha512passwd` and admin-owned keys are preserved/protected across informs).

Package `internal/adminapi`: REST over JSON at the `--listen-admin` addr:
```
GET    /api/v1/devices            (list; state/last_seen are JSON numbers)
POST   /api/v1/devices            {mac, name?, site_id?}  -> idempotent upsert, PENDING record
DELETE /api/v1/devices/{mac}
GET    /api/v1/devices/{mac}
GET    /api/v1/pending            (discovery-found candidates)
POST   /api/v1/pending/{mac}/adopt
GET    /api/v1/wireless           (whole-document WLAN envelope)
PUT    /api/v1/wireless           (replaces the whole document)
GET    /api/v1/whoami
GET    /healthz                   -> 200 ok
GET    /metrics                   (promhttp; requires the token when one is set)
```
Auth: optional `--admin-token <hex>` (env fallback OPEN_UNIFI_ADMIN_TOKEN); when set,
EVERY /api route AND /metrics require `Authorization: Bearer <token>` (401 otherwise) —
only `/` (web console) and `/healthz` stay open. Terraform provider uses this.

Web UI (lane D): static page at `/`:
- list of devices & pending adopters,
- `Adopt` button → POST /pending/{mac}/adopt,
- textarea/dropdowns for: SSID name, passphrase, security (open/wpa-p/wpa-eap),
  VLAN id; save → PUT /api/v1/wireless (whole-document envelope, adminapi shape).

Package `provider` (lane E, at provider/ dir + cmd/tfprovider):
resources `open-unifi_access_point` (adopt, by MAC + controller URL/token),
`open-unifi_wlan` (ssid, security, passphrase, vlan), data source `open-unifi_devices`.
Provider `Configure` accepts `url`, `token` (honest: token required unless server
started without --admin-token).

## 7. Whatever is still uncertain (morning-verify carry-list)

Resolved since the first pass: `mgmt_cfg` text encoding (PROTOCOL-mgmt.md §2),
`system_cfg` format (PROTOCOL-mgmt.md §3 + PROTOCOL-systemcfg-wireless.md), and
cfgversion semantics (match → noop; mismatch → full-provisioning setparam,
PROTOCOL-mgmt.md §6.2 row d).

Still open — verify against the real U7PG2 during the acceptance window:
- ~~Device-reported state enum numeric values~~ RESOLVED (see §3 "state field
  semantics"): 0=UNKNOWN … 11=ISOLATED (Device.txt:11897-11947).
- ~~`noop.interval` wire type~~ RESOLVED: JSON **number** (details below).
- ~~`ieee_mode` ht-width guess~~ RESOLVED (PROTOCOL-systemcfg-wireless.md §3.1:
  resolver min(country limit, HT-mode cap, device caps) ⇒ `11nght20` / `11naht40`;
  tmpwork/javap/com__ubnt__service__devmgr__c.txt:1242-1380).
- `noop.interval` classic value algorithm (documented for reference, open-unifi
  simplified): `interval` is emitted as a JSON number — `Integer.valueOf(10)` on
  the exception-path noop (tmpwork/javap/com__ubnt__service__devmgr__voidsuper.txt:9945-9955)
  and `Long.valueOf(computed)` in the main noop builder (voidsuper.txt:11412-11422).
  The value is load-tiered from the device's last `system-stats` (cpu/mem double
  fields, voidsuper.txt:11182-11226): cpu<50 ∧ mem<90 → 1 s; cpu<50 ∧ mem≥90 → 5 s;
  cpu<75 ∧ mem<95 → 5 s; else the static default 10 s. Steady-state target:
  `max(lastInform + 5, now + 10) + random[0,5)` (voidsuper.txt:11235-11292).
  The servlet response writer itself adds only `server_time_in_utc` — a **string**
  (`Long.toString(epochMillis)`, tmpwork/javap/com__ubnt__net__InformServlet.txt:1569-1580)
  and no interval of its own (InformServlet.txt:1568-1624).
  open-unifi note: simplified to a fixed number (15) for now; load tiering is
  future work.
- Uplink port assumption: `# vlan` rows hardcode `eth0` as the tagged/untagged uplink —
  confirm the U7PG2's actual trunk port (if it is eth1, tagged VLANs break).
- `mgmt_url` port fallback when `--controller-url` is not https (we emit :8443).
- `two_phase_adopt` flows (older firmware only; 6.x adopts in one phase — believed
  irrelevant).
- ~~Discovery response packet exact TLVs~~ — extracted (docs/PROTOCOL-discovery.md
  §2.3/§2.4: `oooO(9,2)` reply = TLV 1 (our MAC) + TLV 2 × interfaces (mac+ip) +
  TLV 3 (FW version) + TLV 21 (shortname-subtype) + TLV 22 (version) + TLV 23
  (setup flag)); open-unifi still sends no discovery replies (TODO, see §4).
