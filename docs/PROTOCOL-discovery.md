# PROTOCOL-discovery — UDP/10001 discovery TLVs (controller ⇄ device)

Companion to `docs/PROTOCOL.md` §4, sharpened to bytecode certainty.
Sources (CFR 0.152 decompiles of `ace.jar` — see the provenance note below):

**Provenance (decompilation artifacts):** the `decomp/…` file names in the table
below refer to the original proguard-renamed `.java` outputs of the CFR
decompiler, produced in a **local, untracked decompilation workspace** — no
`decomp/` directory is committed. The source jar is the controller deb's
`tmpwork/data/usr/lib/unifi/lib/ace.jar`; the canonical, reproducible bytecode
citations are the `javap -c -v` dumps under `tmpwork/javap/**` (also deliberately
gitignored — the decompiled Ubiquiti jar is not our artifact to redistribute).
These `decomp/…` names are kept because line-level claims in the older
revisions trace back to them; re-find any given class via `tmpwork/javap/INDEX.txt`.

| file | formal class | role |
|------|--------------|------|
| `decomp/com__super__A__A__O0oO.java` | `com.super.A.A.O0oO` ("LiteStationQueryServer" thread) | UDP request parser + beacon reply builder |
| `decomp/com__super__A__A__G.java` | `com.super.A.A.G` | socket/thread base, ports, interface MAC/IP list |
| `decomp/com__super__A__A__D.java` | `com.super.A.A.D` (+ nested `_o`, `_Oo`) | parsed device record holder |
| `decomp/c_543cc1988aaa.class.java` | `com.super.A.A.oooO` | UDP packet writer (4-byte header + TLVs) |
| `decomp/c_18fa13593e41`→`c_0029b9f2f7a1` etc. | `o0OO`, `H`, `new`(`_new`), `super` (TLV constants interface) | command abstraction |
| `decomp/c_c13f6af13d0d.class.java` | `com.ubnt.net.K` | **the running discovery service** (Spring bean, implements `U`, `F`, `nullsuper._Ooo`) |
| `decomp/c_06e4f7354dea.class.java` | `com.ubnt.net.o0OO` | test beacon *emulator* (proves TLV meanings!) |
| `decomp/com__super__A__A__G.java` | `G` | MulticastSocket on udp/10001 |

Collector/exported constants verified only where noted; everything else
byte-quoted.

## 1. Service on the controller

`com.ubnt.net.K extends com.super.A.A.O0oO extends G` — Spring bean registered
(`implements InitializingBean`), started via `this.o00000(3, null)` (G socket
bootstrap for 3 sockets). It:

- registers itself as discovery listener (`implements com.super.A.A.F`),
- is wired to `U._o = DiscoveryHandler` (callback interface `com.ubnt.net.U`),
- reads `Setting "mgmt" → "discoverable"` to decide whether beacon replies are
  sent (also auto-enabled when the controller is not yet set up —
  `supersuper.StringObject()` = "setup not completed"):

```java
public void afterPropertiesSet() {
    … logger.debug("started");
    this.o00000(3, null);                                   // open sockets
    this.interfacefloatnew.o00000((nullsuper._Ooo)this);    // config change hook
    this.\u00f5\u00d5\u00d4000 = this.\u00f4\u00d5\u00d4000.thissuper("mgmt").is("discoverable", false);
}
protected boolean cfr_renamed_0() {   // "reply to beacon?" gate (CFR-renamed `while`)
    if (R.\u00f50O000()) {                  // platform check (UNIFI/prod build)
        if (supersuper.StringObject()) return true;         // pre-setup state
        return this.\u00f5\u00d5\u00d4000;                       // mgmt.discoverable
    }
    return false;
}
```

- Ports/addresses, from `G`:
  - UDP port `10001` (G.\u00f6\u00d60000, `MulticastSocket`).
  - Multicast group `"233.89.188.1"` (`O0oO.\u00f5\u00d60000` used in parse fn
    `OOoO.cfr_renamed_0()` for V1 alias? — actually referenced as G base for
    sending: `byte[] superclass = {-23,89,-68,1}` and `{-1,-1,-1,-1}` = the two
    ecosystem broadcast IPs decoded as destination alternatives; the reply
    `DatagramPacket` goes to the device socketAddress directly).
  - `G.classclass = 1`, `G.\u00d2\u00d60000 = 2` = supported *packet versions*.

## 2. Wire formats

### 2.1 Packet header (all versions, `oooO` writer, verbatim)

```java
public oooO(byte by, byte by2) {           // (cmd, version)
    this.\u00d2\u00d50000[0] = by2;             // [0] = version byte
    this.\u00d2\u00d50000[1] = by;              // [1] = command byte
    this.o\u00d50000 = 4;                      // payload starts after 4-byte header
    if (by2 == 2) {                            // V2 header auto-adds TLV 18 + 19:
        this.o00000((byte)18, OOoO.cfr_renamed_0((int)G.\u00f400000()));   // seq no.
        this.o00000((byte)19, G.cfr_renamed_1());                          // sender MAC
    }
}
public void o00000(byte by, byte[] byArray) { // TLV writer
    buf[o++]= by;                             // tag (1 byte)
    buf[o++]=(byte)(len/256); buf[o++]=(byte)(len%256);   // length 16-bit big-endian
    System.arraycopy(value, 0, buf, o, len);  // value
}
public byte[] o00000() {                    // finalize
    …[2] = ((o-4)/256) & 0xff; [3] = ((o-4)%256) & 0xff;   // total payload length BE16
}
```

So on the wire: `[ver:1][cmd:1][payloadLen:2 BE]` then a flat TLV stream of
`[tag:1][valLen:2 BE][value]`. Values are raw bytes; strings are written
`String.getBytes("ISO-8859-1")`.

Parser (`O0oO.o00000(SocketAddress,byte[],int)`) dispatches `by` (=ver):
- `0` → legacy V0 packet; gate `if (n < 15 && byArray[0] != 0) return null;`
  (O0oO_discovery_redump.txt:1331-1341) then reads the flat layout **[mac:6][ip:4][len:4][version-string…]**
  — the length field is a **4-byte big-endian int** parsed with the same
  `OOoO.class([B)` helper as other int fields (O0oO_discovery_redump.txt:1331-1461:
  6-byte copy at offsets 14-37, 4-byte copy/`InetAddress.getByAddress` at
  offsets 39-74, 4-byte length read at offsets 76-103, then a length-prefixed
  version string). An earlier revision wrote "[len:2]"; that field is 4 bytes.
- `1` / `2` → TLV packet with `[cmd:1][dataLen:2BE][TLV…]` (dataLen must fit, else
  invalid V2). `int n4 = n3 + 1 + 1 + 2;` bounds the stream.

### 2.2 Commands (constants `interface com.super.A.A.super`)

Packet versions first: `0, 1, 2`. Commands/constants then defined twice
(command group and "response/flags" group), decompiled values:

```
commands:      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
response-flag: 0x80 (-128), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
```

Verified live values from behavior:

| cmd | direction | meaning | evidence |
|-----|-----------|---------|----------|
| `6` (0x06) | device → controller | info/beacon with aliases | parse switch §366 `by2 == 6 || by2 == -128`; test packet `oooO(6,2)` |
| `8` (0x08) | device → controller | discovery beacon (asking for controller) | §334 `if (by == 2 && by2 == 8) { if (this.cfr_renamed_0() && site-local(src)) this.o00000(socketAddress); … }` — the ONLY path that triggers the reply below |
| `2` (0x02) | device → controller | challenge response (carries TLV 7 salt + 8 challenge + 9 crypted password) | §404 `by2 == 2 || by2 == -126` |
| `2` (0x02) | controller → device | locate (LED blink), via `_new(mac, cmd=5?)`? — actually `new.o00000(...)` uses cmd `5` with TLV 17 = seconds | `K.o00000(U._o)` §159-168 |
| `3` | controller → device | set temporary IP (new.o00000 TLV 4) | `K.cfr_renamed_3` §178-187 |
| `9` | controller → device | **discovery reply** (built by `oooO(9,2)`, see 2.3) | reply builder §513-525 |
| `10` | controller → device | invoke sshd | `cfr_renamed_1(SocketAddress)` §532-541 sends exactly `new byte[]{2,10,0,0}` |

"Command not yet supported." trace covers everything else.

### 2.3 Device → controller beacon (what the device broadcasts)

Emulator class `com.ubnt.net.o0OO` (md5 `06e4f7354dea`, decompiled verbatim)
shows exactly what a UAP gen2 advertises; `oooO(6,2)` = V2 cmd 6 sent to
`255.255.255.255:10001`:

```java
oooO p = new oooO(6, 2);
p.o00000((byte)2,  new byte[]{0,21,109,1,0,1, 10,2,2,1});   // TLV2: 10B = MAC(6)+IP(4), repeatable
p.o00000((byte)1,  new byte[]{0,21,109,1,0,1});             // TLV1: own MAC (6B)
p.o00000((byte)10, OOoO.cfr_renamed_0(3600));               // TLV10: uptime, 4-byte int BE
p.o00000((byte)3,  "BZ.ar7240.v3.1.0.15.150311.1401");      // TLV3: full firmware string
p.o00000((byte)22, "3.1.0");                                // TLV22: short firmware version
p.o00000((byte)21, "BZ2");                                  // TLV21: platform shortname/model hint
p.o00000((byte)23, new byte[]{1});                          // TLV23: default-state byte (1 = factory)
```

Concrete wire bytes for that beacon:

```
02 06 002d
02 00 0a 00 15 6d 01 00 01 0a 02 02 01
01 00 06 00 15 6d 01 00 01
0a 00 04 00 00 0e 10
03 00 26 "BZ.ar7240.v3.1.0.15.150311.1401"
16 00 05 "3.1.0"
15 00 03 "BZ2"
17 00 01 01
```
(header `002d` = 45 payload bytes.)

Full TLV table as parsed on controller side (O0oO switch §158-333, D getters, plus
K.\u300000000(D) key mapping in §134):

| tag | meaning | wire type | parsed into |
|-----|---------|-----------|-------------|
| 1 | device MAC (6 B) must be len 6 | clone | `D.mac` |
| 2 | alias IP entry: MAC(6)+IP(4), len 10, repeatable | class `D._o` | wifi interfaces list (assigned mac+len) |
| 3 | firmware string (full, e.g. `BZ.ar7240.…`) | string | `D.version/name=` — used as `model` fallback |
| 6 | ssh username | string | (challenge flow) |
| 7 | random key/salt (challenge) | bytes | `_new._o(salt,challenge)` |
| 8 | challenge | bytes | same |
| 9 | SHA-256 crypted password | bytes | same |
| 10 | uptime (4 B int BE) | int | `d.uptime` |
| 11 | hostname | string | `d.hostname` |
| 12 | platform (shortname e.g. `UAP`) | string | `D.platform` (`Model.fromString(String)`) |
| 13 | essid | string | `d.essid` |
| 14 | wmode (2 B int BE) | int | `d.wmode` |
| 16 | fingerprint hash (SHA-256 hex of both sender+controller) | hex | `d.fingerprint` (32-hex) — used for SSH `ssh_key` host-key verification |
| 18 | seq number (4 B int BE), anti-replay | int | `D._o.dropped if seq not > previous && <5 s window` (§351-364); also auto-injected on V2 packets |
| 19 | sender MAC echo (6 B) | bytes | `string9`, ignores packets whose MAC equals our own interfaces |
| 21 | model/shortname string | string | `string6` — used for `D.\u300000000(d) = "internal default"?` |
| 22 | (config) generic string | string | `string5` |
| 23 | default-state bool (1 byte, `=device is factory`) | bytes→bool | `d.default` |
| 24 | (check) bool | bytes→bool | `d.cfr_renamed_1(bl2)= adopting-scan flag` |
| 25 | (WEP?) bool | bytes→bool | `d.\u300000005(bl3)` |
| 26 | (footprint-mismatch?) bool | bytes→bool | `d.cfr_renamed_5(bl4)` |
| 27 | config string | string | `d.\u200d4O0000` (unused by K InformServlet but stored) |
| 28 | sshd port (`d.\u200d1O0000`) | int | `d.sshd_port = n7` (default 22, §2861) |
| 33 | string (3G/LTE-part) | string | `d.\u200d4000000` (`lte_iccid`/`free`) |
| 34 | string | string | `d.\u200dcfr_renamed_0` |
| 35 | string | string | `d.\u200d`f800000 |
| 36 | string | string | `d.\u3000000013` |
| 37 | bool | bool | `d.\u300000005(bl5)` |
| 38 | string | string | `string14` |
| 39 | `hash_id` (32 hex, validated `C.\u200df600000(hash)`) | string | `d.hash_id` (`NULLIFY if invalid`) |
| 42 | UUID (2× 8-byte BE) | bytes | parsed UUID string (`string15`) |
| 48 | (support) bool | bool | `bl6` |
| 49 | (4-byte) int | int | `n8` |
| 17 | locate duration (controller → device in `_new`, seconds) | string | `new_.o00000((byte)17, String.valueOf(n))` |
| 4  | new IPv4 address (controller → device, `set tmp ip`) | string | `new_.o00000((byte)4, ip)` |
| 22 vs 21 on **reply**: see §2.4. | | | |

Anything else: `trace("TLV %d data: [%s]", hex-dumped)` and skipped.

Also — filtered MAC emoji list `intclass = ["M2M","M2S","P8U","P6E","P3U","P3E","P1U","P1E","IWO2U","IWD1U"]`
(mFi device shortnames — these beacons are silently dropped, §348-350).

Better name mapping (raw field labels from `D` decomp):
`K.\u300000000(D)` serializes into the "pending device" record used by the UI:

```java
x.put("mac", hex(d.mac));
x.put("serial", hex-uppercase(d.mac));
x.put("ip", d.addr.getHostAddress());        // first alias or source address
x.mergeFrom(X.newInstanceWithoutNullValue(
   {"hostname", d.o00000(), "model", string(d.\u300000000()), "version",
    blank(d.cfr_renamed_3) ? d.thissuper() : d.\u300000000(),
    "default", d.cfr_renamed_4(), "locating", d.\u200dcfr_renamed_1(),
    "using_dhcpc", d.\u200d400000(), "dhcpc_bound", d.\u200d\u3000000(),
    "uptime", d.\u200d\u30000000(), "system_id", d.\u200d4O0000(),
    "required_version", d.\u300000000(), "sshd_port", d.\u30000000 == -1 ? null : d.\u30000000}));
x.put("hash_id", d.\u200d4O0000());
d.oo0000().ifPresent(s -> x.put("anon_id", s));  // TLV-optional analytics id
```
plus LTE/LCM specifics: for `Model.returnclass` (LTE carrier device) adds
`lte_iccid`, `lte_imei`, `lte_radio`; for LTE-other models `lte_iccid`, `lte_imei`,
`lte_is_sim_pin_required`, `lte_sim_pin_tries_left`; for `Model.ifsuper` (UBB) adds
`ubb_pair_id`, `ubb_is_ap`, `ubb_bssid`.

### 2.4 Controller → device beacon reply (cmd 9)

Verbatim (`O0oO.o00000(SocketAddress)` §513-530 + G.\u300000000() list):

```java
oooO reply = new oooO(9, 2);                     // V2, cmd 9
reply.o00000((byte)1,  O0oO.cfr_renamed_4());    // TLV1: our identity MAC (first non-loopback iface HW addr, G.cfr_renamed_2())
for (byte[] a : this.\u00f500000())              // G.\u300000000 per-interface entries:
    reply.o00000((byte)2, a);                    // one TLV2 per interface: 6B MAC + 4B IPv4
reply.o00000((byte)3,  R.\u00f5\u00f50000().toString()); // TLV3: controller FW version object (parse of /usr/lib/version; empty version object on bare metal)
reply.o00000((byte)21, R.return(true));          // TLV21: board.shortname + "-" + board.subtype (properties from /usr/lib/unifi/… info)
reply.o00000((byte)22, R.\u00f8oO000());          // TLV22: controller version string ("version" from ubnt info, "unknown" fallback)
reply.o00000((byte)23, new byte[]{ supersuper.StringObject() ? 1 : 0 }); // TLV23: "controller in setup mode" byte
DatagramPacket(reply.o00000(), len, socketAddress).send();
```

Example reply bytes (iface MAC `00:15:6d:01:00:01`, ip `10.0.2.2`):

```
02 09 LL LL
01 00 06 00 15 6d 01 00 01
02 00 0a 00 15 6d 01 00 01 0a 02 02 02
03 00 05 "7.5.0"      (FW version object toString; empty obj may emit "-.-.-" — UNRESOLVED exact default)
15 00 03 "UCD"        (board shortname;UNK exact controller-side value strings)
16 00 05 "7.5.0"
17 00 01 00
```

⇒ verdict to the open question in PROTOCOL.md: **there is no `inform url` TLV in
the reply.** The reply contains only identity info (mac / interfaces (mac+ip) /
firmware strings / setup flag). The classic UAP learns the inform URL either from
`setparam.mgmt_cfg.inform_url=...` (HTTP inform, docs/PROTOCOL-mgmt.md §2) or from
the adoption command over SSH/TLS (`devmgr/ooOo` JSON `{"type":"adopt", "url":…,
"authkey":…}` on tcp/2022, `devmgr/privatesuper._Oo` →
`/usr/bin/syswrapper.sh set-adopt <url> <authkey>`), **not over UDP/10001**.

Also `O0oO.o00000(D)` throws `IllegalStateException("LiteStation type devices do
not support modification!")` — this server cannot push TLVs (no modifying of V0
devices).

### 2.5 Self-reply guard / anti-replay

- The device beacon's MAC (`string9` from TLV 19) equals our own controller
  identity MAC → packet ignored (§345).
- Per-MAC last-seen in `HashMap<String,_o> O\u200d80000`: if within 5 seconds
  (`\u00d2\u00d80000 = 5`) and seq not newer than last (`n6 <= last`) → packet
  silently dropped.
- Beacon only handled when src address `InetAddress.isSiteLocalAddress()` for reply
  sending when controller `cfr_renamed_0()` gate passes.

## 3. How a device "informs over UDP" (verdict)

- There is **no UDP inform_url advertising** in this controller (Port 10001 reply
  carries no URL, see 2.4).
- `com.ubnt.net.K` explicitly logs on the two relevant `U` interface calls:
  ```java
  public void cfr_renamed_3(String s1, String s2, String s3, String s4, String s5, String s6) {
      logger.error("adopt is not implemented", …);
  }
  public boolean \u300000000(String mac, String u, String p, String s4) {
      logger.error("ResetDefault is not implemented", …); return false;
  }
  ```
  ⇒ neither `adopt` nor `reset` is ever sent over UDP by this controller.
- So device adoption recovery: L2-discovered devices are adopted via SSH/TLS
  channel per docs/PROTOCOL-mgmt.md §7 — the UDP 10001 channel merely
  *announces* the device (to `U._o` = the UI/pending list) and optionally opens the
  door with "invoke sshd" (`02 0A 00 00`, from the base O0oO method — legacy path,
  kept for AirOS/mFi compat).

### 3.5 Device-side reply disposition — the adoption premise, settled (2026-09-20)

Open question (the GUI-adoption premise): does a U7PG2 on fw 6.8.2.15592 act on a
cmd-9 reply by informing the replying controller? Answer, from the AP's own
`/usr/bin/mcad` (Ghidra program `u7pg2-mcad`; evidence plated at
`mcad_discovery_udp_recv`, 0x00421198) plus the live Sep-16 bench capture — **no,
on three independent grounds**:

1. **The reply is undeliverable.** The v2 beacon goes out from an EPHEMERAL source
   port on a socket closed immediately after `sendto`
   (`mcad_discovery_send_packet` 0x0041fd6c: socket → bind(iface) → sendto →
   close, per-interface loop). Live capture `capture-adoption-fid57-20260916.pcap`
   (bench vmbr0, no filter): `10.10.10.20:50791/51280/49987/44806/46459/39791 →
   255.255.255.255:10001`, a fresh port every 10 s (plus the IPv6 twin
   `fe80::feec:…:ephemeral → ff02::1:10001`). The reply targets the beacon's
   source address:port (jar reply path, PROTOCOL.md §4) — a socket already
   closed. The cmd-10 "invoke sshd" poke to the same address is equally dead on
   this firmware.
2. **Even if a v2 packet reaches the persistent `0.0.0.0:10001` socket, cmd 9 is
   never processed.** The socket pair is created and registered by
   `mcad_discovery_establish` (0x00411164; sockets via 0x004200dc; event callback
   thunk 0x00411ab4, arg = `mgmt.discovery.status`, default false). The handler
   `mcad_discovery_udp_recv` (0x00421198) drops ALL v2 packets while
   `/proc/ubnthal/status/IsDefault` (factory state) or `/var/run/system.selfrun`
   is set, skips packets sourced from port 10001, and its only success path
   records cmd-6 peer beacons (TLV 1 mac, TLV 2 ip, TLV 18/19 seq/sender) into
   `/var/run/mcad.discovered/<mac>` — the mesh-peer cache consumed by
   `mcad_mesh_periodic_update` (0x0040b8c0), which fires `syswrapper ssh-adopt`
   only on a mesh-downlink serial match. No branch reads cmd 9.
3. **No UDP path can set the inform URL.** The only writers of
   `mgmt.servers.1.url` / managed state — `reporter_save_config` (0x00412364)
   and `set-managed` (0x00414274) — are called exclusively from
   `mcad_reporter_handle_response_json` (0x00414acc), the inform-response chain
   (docs/AP-FIRMWARE-APPLY-PATH.md §2/§6.5). The v1 lane
   (`mcad_discovery_v1_responder` 0x00421054, gated by `mgmt.discovery.status`)
   is a pure outbound responder to discovery-tool requests.

⇒ The reply emitter (PROTOCOL.md:199 TODO) is protocol-completeness only — it can
never cause an inform from this device. The ONLY lane that delivers an inform URL on
this firmware is the SSH set-inform channel (docs/PROTOCOL-mgmt.md §7), exactly as
§3 concluded. Adoption UX (the console "accept" action) must therefore drive a
controller-side SSH set-inform push. Consistency note: the 2026-09-20 round-2
recovery proved the automated SSH lane works against factory sshd state (the
automation-hostility finding applies to the applied config only) — and the
adoption case IS the factory case.

## 4. UNRESOLVED / explicitly searched & not found

- TLV 16 fingerprint SHA-256 algorithm (which two strings are hashed) — only
  `" [" + hex string + "]"` logging surfaces; not used anywhere on the inform side
  here beyond `ssh_key` host-key store.
- The exact controller-side value strings of TLV21 `board.shortname` /
  `board.subtype` (read from controller build info file); tests would need one
  real reply capture.
- What `TLV 17/4/9/…` map to on the device side (the code only writes, device
  firmware implements them) — partially resolved 2026-09-20 (§3.5): the U7PG2 mcad
  v2 receive path consumes only cmd-6 peer beacons (TLV 1 mac / TLV 2 ip /
  TLV 18 seq / TLV 19 sender-mac echo) into its mesh-peer cache; cmd 9 has NO
  device-side consumer on fw 6.8.2.15592.
- Whether `o\u200d\u30000080` (-128 beacon-ack) exists in the wild: parse accepts
  it like 6 but no special handling.
- `new`/`_new` "${super}" owner for the *challenge* flow on the controller side is
  implemented only for challenge-response *handling* (O0oO §404-443); the
  `locate`/`set-ip` paths don't challenge.
