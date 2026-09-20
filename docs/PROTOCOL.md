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
still TODO in open-unifi — but (2026-09-20, device-side mcad RE, PROTOCOL-discovery.md
§3.5) a reply can NEVER deliver an inform URL on U7PG2 fw 6.8.2.15592: the beacon
leaves from an ephemeral port on an immediately-closed socket (a reply to the beacon's
source address:port is undeliverable), and mcad has no cmd-9 consumer at all (it drops
every v2 discovery packet while in factory state). The reply emitter stays on the list
for protocol completeness only; the adoption lane is the SSH set-inform channel
(docs/PROTOCOL-mgmt.md §7), per line 225 below.
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

## 5. Config blobs (`mgmt_cfg` / `system_cfg`) — WLAN GATED

Live WLAN provisioning is unsupported pending an official-controller
differential fixture. U7PG2 firmware 6.8.2.15592 with any nonempty managed
WLAN is rejected with a typed status and no `system_cfg`.

- `mgmt_cfg`: 10-line text blob (exact line order + the conditional `authkey=` rule):
  **PROTOCOL-mgmt.md §2** (bytecode-cited from the B-writer decompile). Historical
  `unifi.*`-prefixed spellings are superseded.
- `system_cfg`: full AP system config text — sections `# unifi`, `# system`, `# users`,
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
`ssh_sha512passwd` and admin-owned keys — `wlan_cfg_*`, `radio_intent` — are
preserved/protected across informs).

Trust-policy asymmetries (mirror the classic controller's observed behavior;
recorded so they read as fidelity, not oversight):
- `ssh_md5passwd` is not controller-owned: unlike its sha512 sibling, the
  device may overwrite the md5 password cache through an inform. Only
  `ssh_sha512passwd` rides the protection list.
- `Extra["watching"]` is device-writable: nothing protects it, and the noop
  scheduler honors a truthy value with the 5-second watching cadence, so a
  device can select its own fast cadence.
- `has_eth1` is fill-if-absent but never read: the eth inventory derives from
  if_table/ethernet_table (system_cfg renderer), so the key is a vestige the
  classic controller also carries.
- `Extra["radio_intent"]` is admin-owned (2026-09-19): the per-radio
  channel/txpower intent the renderer overlays on the radio_table echo
  (PROTOCOL-systemcfg-wireless.md §3.2). An inform can neither overwrite nor
  introduce it; a forged `radio_intent` in an inform body is discarded.

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
GET    /api/v1/devices/{mac}/radios    (per-radio views: echo fields + intent overlay)
PUT    /api/v1/devices/{mac}/radios/{radio}    {"channel"?: int, "txpower"?: int|"auto"}  -> wholesale replace
DELETE /api/v1/devices/{mac}/radios/{radio}     (clear the radio's intent; echo-only again)
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
- textarea/dropdowns for: SSID name, passphrase, security (open/wpa-p/
  wpa-eap). wpa-eap needs an inline RADIUS profile (up to 4 auth servers
  "ip"/"ip:port", shared secret, dynamic-VLAN mode); passphrase is
  optional there (≥8 when set).
  VLAN id; save → PUT /api/v1/wireless (whole-document envelope, adminapi shape).

Package `provider` (lane E, at provider/ dir + cmd/tfprovider):
resources `open-unifi_access_point` (adopt, by MAC + controller URL/token),
`open-unifi_wlan` (ssid, security, passphrase, vlan), data source `open-unifi_devices`.
Provider `Configure` accepts `url`, `token` (honest: token required unless server
started without --admin-token).

## 7. Carry-list — closed by live acceptance (2026-09-16)

Resolved since the first pass: `mgmt_cfg` text encoding (PROTOCOL-mgmt.md §2),
`system_cfg` format (PROTOCOL-mgmt.md §3 + PROTOCOL-systemcfg-wireless.md), and
cfgversion semantics (match → noop; mismatch → full-provisioning setparam,
PROTOCOL-mgmt.md §6.2 row d).

Resolved against a real U7PG2 (see the acceptance log at the end of this
section):
- ~~Device-reported state enum numeric values~~ RESOLVED (see §3 "state field
  semantics"): 0=UNKNOWN … 11=ISOLATED (Device.txt:11897-11947).
- ~~`noop.interval` wire type~~ RESOLVED: JSON **number** (details below).
- ~~`ieee_mode` ht-width guess~~ RESOLVED (PROTOCOL-systemcfg-wireless.md §3.1:
  resolver min(country limit, HT-mode cap, device caps) ⇒ `11nght20` / `11naht40`;
  tmpwork/javap/com__ubnt__service__devmgr__c.txt:1242-1380).
- ~~Uplink port assumption (`# vlan` rows hardcode `eth0`)~~ RESOLVED: the live
  U7PG2 reports a single eth interface — `if_table` = `[{name: "eth0", up:
  true}]`, `uplink = eth0`, `has_eth1 = false` — so eth0 is the trunk uplink and
  the hardcoded eth0 rows are correct. `port_table` does list a second port
  (port_idx 2, `Secondary`, `is_uplink: false`, media GE) but its names are
  labels, not ifaces, and the device reports no eth1 interface; deriving a port
  count from it would invent one. 6.8.2 sends **no** `ethernet_table` in
  informs, so `ethPortNames` derives real `ethN` names from `if_table` (falling
  back to the learned `uplink`) before the last-resort eth0 default (FID-2).
- ~~`mgmt_url` port fallback when `--controller-url` is not https (we emit
  :8443)~~ RESOLVED: the device never contacts :8443. A live 60 s watch on the
  controller host saw zero packets to the mgmt port; the U7PG2 stays connected
  purely via `:8080` informs (adoption and steady state).
- ~~`two_phase_adopt` flows (older firmware only; 6.x adopts in one phase —
  believed irrelevant)~~ RESOLVED: 6.8.2 adopts in one phase. Observed a single
  `setparam` adoption push encrypted with the factory default key, then key
  rotation (`ba86…` → `a066…`) and a re-inform 476 ms later; no second phase.
- ~~Discovery response packet exact TLVs~~ — extracted (docs/PROTOCOL-discovery.md
  §2.3/§2.4: `oooO(9,2)` reply = TLV 1 (our MAC) + TLV 2 × interfaces (mac+ip) +
  TLV 3 (FW version) + TLV 21 (shortname-subtype) + TLV 22 (version) + TLV 23
  (setup flag)); open-unifi still sends no discovery replies (TODO, see §4).
  Live note: replies are **not required** for adoption — the device adopted via
  set-inform with zero server-side UDP/10001 traffic (announcements were parsed
  correctly and ceased after adoption).
- ~~Snappy inform payloads (flag `0x04`)~~ RESOLVED: 6.8.2 never sets the bit.
  Flags were `0x0003` (encrypted + zlib, CBC) pre-adoption and `0x000b`
  (encrypted + zlib + AES-GCM) post-adoption; `ErrSnappyUnsupported` never
  fired.

`noop.interval` is emitted as a JSON number. The exception/non-record fallback
is `Integer.valueOf(10)` (tmpwork/javap/com__ubnt__service__devmgr__voidsuper.txt:9945-9955).
For an ordinary non-ubios UAP, the standard path is steady scheduling, not the
cpu/mem `Stringclass` load tier: its target is
`max(previous target + 5, current inform timestamp + 10) + floor(random[0,1)*5)`
(voidsuper.txt:11235-11292), and the returned interval is target minus the
current inform timestamp. If that interval is below the configured
`inform.interval` cap, the target is persisted and returned; otherwise the
fallback is `floor(cap * (1 - 0.7 * random[0,1)))`. The jar default cap is 90
(voidsuper.txt:20618-20625). A device marked `Extra["watching"]` truthy gets 5
seconds. cpu/mem `Stringclass` is called only for `isUbios` devices (UDM/UXG);
this implementation intentionally does not model that tier or wifiman-active.
The implementation boundary is the server's record-aware normal noop path;
internal-error, non-record, and plain fallback noops remain interval 10.
The servlet response writer itself adds only `server_time_in_utc` — a **string**
(`Long.toString(epochMillis)`, tmpwork/javap/com__ubnt__net__InformServlet.txt:1569-1580)
and no interval of its own (InformServlet.txt:1568-1624).
open-unifi implements the standard non-ubios UAP path above; load tiering is
not used for UAPs.

### Live acceptance log (2026-09-16)

Device: UAP-AC-Pro-Gen2 (U7PG2), firmware 6.8.2.15592
(`BZ.qca956x_6.8.2+15592.260126.1358`), MAC `aa:bb:cc:dd:ee:02`.
Controller: open-unifi on 10.10.10.10 with `--controller-url http://10.10.10.10:8080`,
`--discovery`, admin `:8443` (plain HTTP + token).

Sequence observed (server.log, UTC+2):
1. 12:48:13–12:49:03 — the device broadcasts 243-byte discovery announcements
   every 10 s (`255.255.255.255:10001` + `ff02::1:10001`), `factory=true`; the
   listener parses uptime/model/ip/factory correctly.
2. 12:49:06 — promoted to pending (state 1).
3. 12:54:30 — adoption push (`setparam`) encrypted with the factory default key.
4. 12:54:31 — the device re-informs with the rotated per-device key 476 ms
   later; flags switch `0x0003` → `0x000b` (GCM on). Adoption complete (state 3).
5. 12:56:10 — test WLAN provisioned (`wireless config replaced, wlans=1`); the
   device's `vap_table` reports state RUN.
6. 13:02:30 — post-restart full `system_cfg` push (`ours=5ffc2d4136d8a5c6`
   replacing `device=401faa42ae99784b`); every subsequent device inform echoes
   `cfg=5ffc2d4136d8a5c6`, i.e. the device confirmed running the generated
   config.
7. Steady state since — connected noops at the server-set 15 s interval;
   discovery announcements ceased after adoption.

Evidence artifacts: the controller log plus a full session capture (`tcp port
8080 or udp port 10001`) on the controller host — candidate input for the
FID-57 jar-anchored differential harness.
