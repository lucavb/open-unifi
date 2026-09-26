# PROTOCOL-mgmt — inform responses & config blobs (classic AP / U7PG2 lane)

Companion to `docs/PROTOCOL.md` (which it amends where noted). Every fact below is
derived from CFR 0.152 decompiles of `ace.jar` classes; each claim cites the class
and a verbatim snippet. Decompiled sources used:

**Provenance (decompilation artifacts):** the `decomp/…` file names in the table
below refer to the original proguard-renamed `.java` outputs of the CFR
decompiler, produced in a **local, untracked decompilation workspace** — no
`decomp/` directory is committed to this repository. The source jar lives at
`tmpwork/data/usr/lib/unifi/lib/ace.jar`; the canonical, reproducible bytecode
citations are the `javap -c -v` dumps under `tmpwork/javap/**` (also deliberately
gitignored — the decompiled Ubiquiti jar is not our artifact to redistribute).
The existing `decomp/…` citations are kept for historical traceability; to
re-verify any claim, locate the class in `tmpwork/javap/INDEX.txt`.

| name | jar class | formal name |
|------|-----------|-------------|
| `decomp/voidsuper.java`, `c_956a5d5649fe.class.java` | `com/ubnt/service/devmgr/voidsuper.class` | inform dispatcher |
| `decomp/c_e9bb4be74abe.class.java` + `c_cf8384dbe7ae.java` | `com/ubnt/net/InformServlet(.class/$_O0)` | HTTP inform servlet |
| `decomp/config_nullsuper.java` | `com/ubnt/service/config/nullsuper` | config dispatcher |
| `decomp/OoOo_beanbase.class.java`, `S_generic.class.java`, `if_Atheros.class.java`, `A_Broadcom.class.java` | `config/OoOo`, `config/S`, `config/if`, `config/A` | device beans |
| `decomp/config_String.java` (re-run w/o rename shows `super(Device)`) | `com/ubnt/service/config/String` | abstract AP bean base |
| `decomp/config_int.java` | `com/ubnt/service/config/int` (90 KB) | AP config builder |
| `decomp/config_B.class.java` (md5 `0ee7457b9057...`) | `com/ubnt/service/config/B` | **mgmt_cfg writer** |
| `decomp/O00O_blockedsta.java` (md5 `359c3dbb2cb6...`) | `com/ubnt/service/config/O00O` | blocked_sta writer |
| `decomp/c_18fa13593e41.class.java` | `com/ubnt/net/Object` | response envelope class |
| `decomp/ace_C.java` | `com/ubnt/ace/C` | line writer helper |
| `decomp/com__ubnt__service__config__L.java` | `com/ubnt/service/config/L` | URL/key helper |
| `decomp/super_A_OOoO.java` | `com/super/A/OOoO` | crypto + byte helpers |
| `decomp/com__ubnt__service__devmgr__ooOo.java`, `privatesuper.java` | `devmgr/ooOo`, `devmgr/privatesuper` | SSH/TLS adoption |

## 1. The `mgmt_cfg` production chain (hypothesis (a) from PROTOCOL.md §5 — RESOLVED)

`nullsuper.forsuper(Device)` (un-renamed decompile, exactly as in code):

```java
public String forsuper(Device device) {
    return this.\u00f4o0000(device).cfr_renamed_3(device);   // = bean.super(device)
}
```

The method really named **`super(Device)`** is simply an illegal Java identifier in
source (like the class names); CFR renames the *call site* to `cfr_renamed_3` but the
*declaration site* decompiles as `public String super(Device device)`. It is declared
in interface `com.ubnt.service.config.o0oO` and implemented by bean `b`
(`b.super(device)` single-delegate) — see `decomp/c_*` of `config/b.class`
(md5 `311cd49cdede...`):

```java
public class b extends OoOo {           // OoOo implements o0oO, OOoO, Q, E
    public String super(Device device) {
        return this.O\u00d40000.super(device);          // delegates to config.B
    }
```

For a **U7PG2** the bean picked by `\u00f4o0000(Device)` is `config/if`
(`device.isAtherosAP()` → `getBean(_if.class)`, config_nullsuper.java §597/296…):

```java
if (device.isAtherosAP())  return getBean(_if.class);      // U7PG2 is Atheros
if (device.isBroadcomAP()) return getBean(A.class);        // A extends int too
```

Both `if` and `A` are thin shells over `com.ubnt.service.config.int`:

```java
public class if extends int { … }        // config/if.class == config/A.class size (2662 B)
```

`int extends String extends OoOo`, and the abstract base `String` implements:

```java
public java.lang.String super(Device device) {
    return this.\u00d2\u00d40000.super(device);   // \u00d2\u00d40000 = private o0oO = new B(r,j2,nullsuper2,l)
}
```

⇒ **mgmt_cfg for classic APs = B (com/ubnt/service/config/B.class) output.** It is
*not* built in `int` (that builds only system_cfg / blocked_sta / by-name config).

## 2. `mgmt_cfg` exact content (config/B.class)

Bytecode-verified writer (`cfr_renamed_0` in CFR output = the illegal `super`):

```java
public String cfr_renamed_0(Device device) {           // == super(Device)
    String siteId = device.getString("site_id");
    X siteExtra = this.\u00d300000.privatesuper(siteId);
    StringBuilder …(1024);
    String selfrun = "pass".equals(siteExtra.getString("config.selfrun_guest_mode","pass")) ? "pass" : "off";
    ArrayList caps = new ArrayList(); caps.add("notif");
    if (siteExtra.is("config.beta.fastapply", "usw".equals(device.getType()))) caps.add("fastapply-bg");
    caps.add("notif-assoc-stat");
    boolean disabled = "uap".equals(device.getType()) && device.is("disabled", false);
    String ledOverride = device.getString("led_override","default");
    boolean ledOn = !disabled && ("on".equals(ledOverride) || "default".equals(ledOverride)
                    && settings("mgmt").is("led_enabled", true));
    C.o00000(sb, "capability",        caps joined with ",");
    C.o00000(sb, "selfrun_guest_mode", selfrun);
    C.o00000(sb, "cfgversion",        device.getString("cfgversion"));
    C.o00000(sb, "led_enabled",       ledOn ? "true":"false");
    C.o00000(sb, "stun_url",          stunHelper.\u00d3O0000(device));   // L
    C.o00000(sb, "mgmt_url",          L.while(device));                // see below
    if (R.o\u00d3O000() && device.isUDM()) C.o00000(sb,"is_setup_completed", setupDone);
    if (device.x_inform_authkey != device.x_authkey) C.o00000(sb,"authkey", device.getString("x_authkey"));
    if (override_inform_host || migrate_inform_url)  C.o00000(sb,"inform_url", L.\u00d300000(device));
    C.o00000(sb, "use_aes_gcm", "true");
    C.o00000(sb, "report_crash", "true");
    return sb.toString();
}
```

Line format comes from `com.ubnt.ace.C.o00000(StringBuilder,String,String...)`:

| args | output |
|------|--------|
| 0 extra | `key\n` |
| 1 extra | `key=value\n` |
| pairs | `key.sub=v\n` per non-null pair |

Byte-level verdict: **plain UTF-8/Latin-1 text, `key=value`, `\n` separators, no
quoting, no base64, no length prefixes.** The whole string is one JSON string value
inside the inform response (`setparam.mgmt_cfg`), so it only gets JSON-string
escaping (`\\n` inside the JSON), nothing else.

`mgmt_url` is `com.ubnt.service.config.L` method (CFR name `while(Device)`):

```java
https://<host>[:443]/manage/site/<site.name>       // when https port == 443
https://<host>:<8443-default>/manage/site/<name>   // else (supersuper.\u00f5\u00d40000() default 8443)
```
(host = `L.cfr_renamed_0(device)` → migrate_inform_url host ‖ override_inform_host
hostname ‖ device.inform_url host ‖ device IP; see L decompile §112-133.)

`stun_url` = `stun://<same host>:<stun port>` (`stun.type=local` → device host;
`stun.type=ubic` → `stun.ubic.device_host`), port `unifi.stun.port` default **3478**
(`supersuper.o\u00d80000()`).

`inform_url` = `http://<host>:<port>/inform`, port `unifi.http.port` default
**8080**; host per `L.o00000(device,false)` priority:
`migrate_inform_url` → `mgmt.override_inform_host`/`identity.hostname` →
`device.inform_url` host → device.ip.

### Key-name cross-check (was an open question)

- The auth key line is exactly **`authkey=<32 hex>`** — NOT `unifi.x_authkey`,
  NOT `mgmt.x_authkey`. It is emitted **only** when the device's applied key
  (`device.x_inform_authkey`) differs from `device.x_authkey` (i.e. key rotation
  pending). B decompile: `if (string != null && !StringUtils.equals(x_inform_authkey, x_authkey))` line `authkey`.
- **No SSH/passphrase settings travel in mgmt_cfg**; SSH creds go into `system_cfg`
  (`users.1` / `sshd.*` lines, config_String.java §184-337).
- PROTOCOL.md §2/§3 (`unifi.cfg_version=`, `unifi.x_authkey=`) is **wrong for this
  controller build**; supersede with this document.

### New-device auth key

- Adopted: `device.x_authkey = C.o00000("0123456789abcdef", 32)` (32 hex chars,
  16-byte AES-128 key) — voidsuper.java:1341.
- Factory/unknown devices: `com.ubnt.net._interface` (decomp `lookup_int.java`)
  returns literal `"ba86f2bbe107c7c57eb5f2690775c712"`; last-resort key list for a
  device is `[device.x_authkey, defaultkey]` (voidsuper.java:1970,1984).
- Decryption candidates per inform: `device.get("authkeys")` list, tried in order
  (InformServlet §349-380); failure → `InformServlet._oo("Unable to decrypt", mac)`
  → HTTP 400.

## 3. `system_cfg` (AP text config, bean `int`)

`nullsuper.\u00f5o0000(Device)` → `bean.\u00d300000(Device)` → `int.\u00d300000(Device)`
(config_int.java §1878-2019). Shape: `new StringBuilder(8192)`, sections appended in
this order for a non-Element AP (`device.isElementDevice()` false → else-branch;
head order verified at javap int.txt:17208-17221 — the unifi writer
`Ó00000(sb,Device,Setting)` runs FIRST, then `class(sb,Device)`, then
`Ó00000(sb,Device)`, then the headerless ledbar `Ò00000(sb,Device,Setting)`):

1. `# unifi` — `unifi.version=<ctrl version>`, `unifi.anonymous_controller_id`, `unifi.anonymous_site_id`, `...reporterid`, `...siteid`, `unifi.idp` (setting `unifi_idp_enabled`, jar default **enabled** — `Setting.is("unifi_idp_enabled", true)`, javap String.txt:1899-1902), then idp-gated rows emitted only when enabled: `unifi.mcip=239.254.127.63`, `unifi.key=<mgmt x_mgmt_key>`, `mgmt.ubic.env` (config_String §184-197; pair order at String.txt:1851-1930); + `unifi.cfgcap_info=0x<mask>` appended by the `int` override (javap int.txt:16600-16630) — mask derived from the controller version (`int.Ô00000()I`, int.txt:5332-5387): ≤2.x → `0x0`, v3.0-3.2 → `0x3`, v3.3+/v4+ → `0x7`. open-unifi deliberately emits `unifi.idp=disabled` (no IDP feature); see §12 of PROTOCOL-systemcfg-wireless.md
2. `# system` — `system.analytics.status`, `system.monitor.memory.threshold=90` (U6-LCM models), `system.timezone`/`locale.timezone` (both skipped when the site locale is absent), `system.resetbtn` (config_String §147-172)
3. `# users` — `users.status=enabled`, `users.1` (name=`L.\u00f400000(device)`=`ubnt`, password = sha-512 (`\u00d4O0000`) or md5 (`\u00f500000`) of site `mgmt.x_ssh_password` default `ubnt`, or `\u00d800000` crypted variant), `users.2=nobody`
4. `# mgmt` ledbar block — HEADERLESS (no `#` row): `ledbar.status`, `ledbar.persistent`, `ledbar.brightness`, `ledbar.active`, `ledbar.color.1.{color,r,g,b}` (`Ò00000(StringBuilder,Device,Setting)`, config_String §2566-2745, called at int.txt:17221)
5. WLANs: `cfr_renamed_1(sb, device, …)` — `wireless.<n>.…`/`aaa.<n>…`/`rmon` lines (config_int §530-etc, `aaa.<n>` has `driver=madwifi`, wpa group_rekey, p2p, proxy_arp, …)
6. vWire/`cfr_renamed_1(... setting ...)` guest controls; `# vlan`, `# bridge`, `# bonding` (`cfr_renamed_0`)
7. `cfr_renamed_1(builder, device, _Oo2 = Stringnew._Oo qos plan)` → `# bandsteering`, `# airtime`, `# mesh`, `# stamgr`, `# qos`, `# mac`/`# connectivity` overrides
8. `# linkcheck echo server` (UDM-family only), `# syslog` + `syslog.remote` + `netconsole` (config_String §207-247), `baresip`, `snmp` (`\u00f800000` → SNMP community `cfr_renamed_1(builder, device, "", "community", 256)`), `# no`-section (`\u00d600000`, no-op for the device), `sshd` (`\u00d400000` — `sshd.status`, `sshd.auth.key.<n>.*` from `mgmt.x_ssh_keys`, `sshd.1.status/ifname`)
9. `# resolv` + `# route` + `# iptables`(mark-based) + `# cron` + `# ntpclient`
10. Appendix: `# misc` then site override lines:
    ```java
    while ((string = x2.getString(String.format("config.system_cfg.%d", n2))) != null) {
        C.o00000(stringBuilder, string, new String[0]);   // raw pre-formatted line
        ++n2; }
    // then per-MAC variant: format "config.system_cfg.%s.%d" with lowercased MAC
    ```
    i.e. admin field `config.system_cfg.<idx>` / `config.system_cfg.<mac>.<idx>` are
    appended **verbatim** (they must already contain the full `key=value` text).
    The two-phase/`privatesuper` variant (§2021-2103) ends at `# misc` without the
    custom config.system_cfg lines.
11. Result: `stringBuilder.toString()`.

`nullsuper.privatesuper(Device)` → `bean.\u00d400000(Device)` = same builder with
guest/hotspot sections courted off and always-stage — the second (empty) config
pushed during two-phase adoption and UDM/Element full-write.

## 4. `blocked_sta`

`nullsuper.\u00d8o0000(Device)` → `bean.\u00d200000(Device)`; for AP beans,
`int.\u00d200000` delegates to `config/O00O` (`intreturn` field, `int` §152/194):

```java
public String \u00d200000(Device device) {
    C c = new C._o().\u00d400000("site_id", device.getString("site_id"))
                      .\u00d400000("blocked", true).o00000();
    List users = this.class.new(User.class, c);           // clients marked blocked
    return users.stream().map(u -> u.getString("mac")).collect(Collectors.joining("\n"));
}
```

Byte-level: **newline-joined MAC list, empty string when no blocked clients.**

## 5. Inform response envelope

Servlet: `com.ubnt.net.InformServlet` (`decomp/c_e9bb4be74abe.class.java`).
Request-side extraction & injection (verified):

```java
public static final int magic = 1414414933;              // 0x544E4255 = "TNBU"
"_mac" = header MAC; "_authkey" = key string used to decrypt;
"_encrypted" = payload was encrypted; "_devid", "_devextip", "_protoheader",
"_devsiteid", "_id" = injected from device record; X-Forwarded-For overrides remote IP.
```

Response write (`cfr_renamed_1(HttpServletResponse, Object, X)`):

```java
object.put("server_time_in_utc", Long.toString(new Date().getTime()));  // EVERY response
if (x.is("_encrypted")) {      // i.e. the device encrypted its request
    byte[] json = X.serialize(object, true).getBytes();
    _O02.\u00d800000 = C.\u00d500000(16);              // NEW random 16-byte IV — set for BOTH branches, BEFORE the if
    if (_O02.cfr_renamed_3()) {                        // request had flags & 0x08 (GCM bit)
        _O02.\u00d500000 = 9;                          // FLAGS = 0x0009 (EncCBC|GCM) — NOT dataVersion
        _O02.\u00d300000 = json.length + 16;           // dataLength includes the appended 128-bit tag
        payload = AES/GCM(json, key = hex2bytes(x.getString("_authkey")),
                          nonce = IV, aad = _O02.\u00d200000(),
                          tag appended);
    } else {
        _O02.\u00d500000 = 1;                          // FLAGS = 0x0001 (EncCBC)
        payload = AES/CBC/PKCS5(json, key = hex2bytes(x.getString("_authkey")), IV = the fresh IV above);
        _O02.\u00d300000 = payload.length;
    }
    contentType = "application/x-binary";
    write(_O02.\u00d400000());                          // serialize: header + payload
} else {
    object.serializeTo(response.getWriter(), true);    // plain JSON
}
```

**Field-map correction** (verified against decomp `c_cf8384dbe7ae.java`, `InformServlet$_O0`;
supersedes any earlier rendering of this block that reads "dataVersion = 9"):

- `\u00d500000` is the **flags** field: `\u00d600000()` = flags&1 (encrypted), `cfr_renamed_3()` =
  flags&8 (GCM), `cfr_renamed_4()`/`\u00d300000()` = zlib&2 / snappy&4; `toString()` prints
  "Flags: …". `OO0000` is **dataVersion** ("Data Version: …"). The response path never assigns
  dataVersion ⇒ **the response dataVersion echoes the request's (= 1)**.
- `\u00d200000()` clones the packet's *current* field values (empty payload) and serializes them
  to 40 header bytes. It is evaluated *after* the IV/flags/dataLength mutations ⇒ **GCM AAD is the
  response's own 40-byte header — exactly the bytes prepended on the wire**. The device reproduces
  the AAD from the plaintext response header it receives, NOT from its request header.
- Echoed from the request, unmutated: magic, packet version, MAC, dataVersion. The response's
  own values: flags (0x0009 GCM / 0x0001 CBC), IV (fresh random, both branches), dataLength
  (json+16 for GCM / ciphertext length for CBC).

Crypto helpers (`decomp/super_A_OOoO.java`): GCM = `AES/GCM/NoPadding`,
`GCMParameterSpec(128, iv)`, `updateAAD(aad)`; CBC retry = PKCS5 first, NoPadding
fallback on BadPaddingException (both directions). **Key = 16 bytes from the
32-hex-char authkey string** (`OOoO.\u200d200000(String)` hex decode).

Plaintext inform requests are rejected unless debug build:
```java
if (!R.ØÒO000()) throw new _o0("Plain text inform is not supported");   // R.ØÒO000() = debug build.type flag
```
and `service()` returns 503 while controller status is not ready.

Sentinel responses returned by `devmgr.voidsuper` (decomp `c_18fa13593e41.class.java`):

| value | meaning in servlet |
|-------|--------------------|
| `Object.\u00f8O\u00d3000` (`new Object("noop")`) | clocked out / two-phase ignore — serialized & sent back as a real `noop` |
| `Object.\u00d5o\u00d3000` (`new Object(null)`) | invalid inform → HTTP 400 |
| `Object.\u00d6o\u00d3000` (`new Object(null)`) | unknown device → HTTP 404 |

Partial-response errors: 400 decode/parse, 408 incomplete, 404 unknown MAC
(InformServlet §143-180). Log lines at info show `<<< [setparam] dev[…] {key sets}`
and `<<< [cmd x] …` for ops visibility.

## 6. Full catalog of inform response shapes (U7PG2 lifecycle)

`Object` (`com.ubnt.net.Object`) is just an `X` map with `_type`. All shapes built in
`devmgr.voidsuper` / `c_956a5d5649fe.class.java`:

### 6.1 `noop`
Sent whenever the per-inform handler finishes with nothing to schedule:
```java
object = new Object("noop");
object.put("interval", nextInterval);                 // ad-hoc device-specific seconds
if (!bl || bl2) object.put("immediate", 1);           // bl = success path, bl2 = pending work / not fully connected
if (device.isAP() && x.is("fingerprint_req")) object.put("fingerprint", [arp/mac table list]);
object.put("server_time_in_utc", …);                  // injected by servlet
```
`interval` = `Stringclass()` load-based (1/5/10 s tier) merged with saturation smoothing
(§1629-1674). Trigger paths: post-task ack, inform errors (fixed 10), state follows,
`upgrade`/`cmd`/`setdefault` after-crash, config-path "skip inform" branches.

### 6.2 `setparam` (config push)

There are exactly 5 emission sites in the main dispatcher (`voidsuper`):

| # | trigger | keys sent |
|---|---------|-----------|
| a) §1117-1125 | adopted via L2 SSH job success (`device.is("discovered_via","l2")` / state just set) | `mgmt_cfg` |
| b) §1148-1156 | inform_url/inform_ip changed, device cfgversion == current | `mgmt_cfg` |
| c) §1268-1272 | device state != connected and unsupported / aesGcmInformEncryptionOnly / cloud disabled — i.e. provisioning pending pre-conditions | `mgmt_cfg` (+ fresh 16-hex cfgversion stored) |
| d) §1316-1329 | **full provisioning** (`device.cfgversion != payload.cfgversion`) | `cfgversion` (= device expected, 16 hex), `system_cfg`, `blocked_sta`, `mgmt_cfg` |
| e) §1391-1400 | device came back from disconnect (`!consideredConnected`) | `blocked_sta` |
| f) §1348 (+§3086/3105/3112 helpers) | x_authkey rotation pending | `mgmt_cfg` |

Also `§855` two-phase adoption: `setparam { mgmt_cfg }` alone (bring device mgmt up
to date before upgrade — see 6.6).

Full-provisioning body example:

```json
{ "_type": "setparam",
  "cfgversion": "e64a9f2c10b8715d",
  "system_cfg": "<aper-text config, see §3.10-3.11 below>",
  "blocked_sta": "aa:bb:cc:dd:ee:ff\n11:22:33:44:55:66",
  "mgmt_cfg": "capability=notif,notif-assoc-stat\nselfrun_guest_mode=pass\ncfgversion=e64a9f2c10b8715d\nled_enabled=true\nstun_url=stun://192.0.2.1:3478/\nmgmt_url=https://192.0.2.1:8443/manage/site/default\nauthkey=6c4...32hex...\nuse_aes_gcm=true\nreport_crash=true",
  "server_time_in_utc": "1726432000000" }
```
(new 16-hex `cfgversion` is generated whenever the controller triggers provisioning:
`cfr_renamed_1(device,"cfgversion", C.o00000("0123456789abcdef",16))` at §501, §676,
§826, §1117/1122, §1269, §3068).

> **open-unifi note (blocked_sta):** rows (d) and (e) are implemented ONLY as
> (d): a change to the blocked-client set rides full provisioning through the
> same mint-then-emit machinery as a WLAN envelope change, and the set lives
> in the device record as an admin-owned row a device body can neither write
> nor introduce. Variant (e) — the reconnect-only `blocked_sta` push — is a
> NAMED follow-up, `blocked_sta-reconnect-push`: open-unifi has no
> connected/disconnected session tracking yet, so there is no
> `!consideredConnected` event to hang it on. Deviation: the list is emitted
> in sorted order (the record stores a canonical sorted set); the real
> controller's order comes from Mongo natural order, which is unrecoverable
> from the jar — treat exact order as a live-proof obligation, not a
> byte-exactness claim.

### 6.3 `cmd` (task passthrough)

```java
private Object o00000(Device device, Task task) {
    Object object = new Object("cmd");
    object.mergeFrom((X)task);            // task MONGO fields become response keys verbatim
    this.\u00d300000(device, task);        // task cleanup/side effects
    if (device.isUnsupported() && !allowedTypes) return Object.\u00f8O\u00d3000;
    return object;
}
```
i.e. a stored Task (cf `Task._type=scheduled` rows like
`{"cmd":"restart","mac":…,"type":…"}` queued through the UI / REST) is replayed JSON
verbatim on the next inform hook `task != null` → §1353-1359. Specific built-in
outgoing cmds implemented NOT as tasks but inline by voidsuper/plugins:
- `get-elite-token` `{cmd:"get-elite-token", ubic_uuid:…}` (§1407-1412, §3376)
- `clear-all-dpi-counters` (§1961), `hide-lcm-tracker`, `show-lcm-tracker`(+`tracker_seed`) (§3142-3144), `send-crashlog`/`send-recovery`/`send-trace`/`clear-*` (§3416-3440)
- `spectrum-scan`, `element-upd` recognized by servlet logging (§132-136)

`setparam`-as-task ack (notif as `setparam` from device → controller gets
`notif_reason=setparam` — no response task; the `cmd-provision` notif returns
a new schedule with delayed `next_interval`).

### 6.4 `upgrade`
`o00000(device, fwVersion, model, …)` (voidsuper §796-822):
```java
object = new Object("upgrade");
// device-upgrade path:
object.put("version", fwVersion);
object.put("url", <firmware url>);           // L.o00000(device, "BZ.ar7240.v…bin") → http://<ctrl-host>:<inform_port>/dl/firmware/<file>
object.copyAttrsIfPresent(x, new String[]{"md5sum","sha256sum"});
// legacy 4.0.x BZ2/BZ2LR/U2O/U5O multi-step:
object.put("version","4.0.10"); object.put("url","http[s]://dl.ubnt.com/unifi/firmware/BZ2/4.0.10.9653/BZ.ar7240.v4.0.10.9653.181205.1311.bin");
```

### 6.5 `reboot`
```java
string11 = new Object("reboot");
string11.put("reboot_type", "soft");                  // only from reboot_on_connect flag
```

**open-unifi (2026-09-19 lifecycle lane).** Implemented. Arming rides the
jar-verbatim record flag `reboot_on_connect`, set only by the admin route
`POST /api/v1/devices/{mac}/reboot` (an admin-owned Extra row — no inform
body can introduce, forge or clear it). The device's NEXT decoded inform
answers exactly `{"_type":"reboot","reboot_type":"soft","server_time_in_utc":"<ms>"}`
on both the CBC and GCM lanes, sealed in the request's own key, and the
flag is consumed in the same decision (one-shot). No cfgversion is minted
at arming or emission: the §6.2 mint-site list (§501, §676, §826,
§1117/1122, §1269, §3068) has no reboot site. The post-reboot re-inform
on the retained key re-enters the ordinary decisions (§6.1 noop /
§6.2 d full provisioning), which is the flow the 2026-09-18 A2 live
reboot round already proved on hardware.
Unrecoverable from the decompile (live-proof obligations): the emission
SITE of the reboot branch inside the dispatcher is not line-pinned (the
byte shape is), so its ordering against the §11006+ default-key state
gate and the drift machinery is our placement, chosen to keep the
armed-command-outranks-everything contract; and whether the real
controller persists the armed flag across controller restarts or re-sends
it (e.g. from a DB with the row always present until a successful
emission) is unproven. Closely related and equally unproven: the
dropped-response case — the flag is consumed in the same decision that
emits, so if the sealed response cannot be written (a sealing failure
falls back to a plain-JSON noop; the socket can drop), the armed command
is silently lost; whether the real controller re-sends an armed command
until the device acks, or loses it the same way, is exactly the re-send
question above.

**open-unifi (2026-09-26 materialization watchdog addendum).** The arming
writer list above is superseded: the engine's devname materialization
watchdog (2026-09-26 production incident; see the same-dated addendum in
docs/WLAN-ACCEPTANCE-6.8.2.15592.md) now also arms `reboot_on_connect`
AUTONOMOUSLY — one shot per cfgversion, guarded by the
`wlan_cfg_materialization_reboot` marker. The marker and the
`wlan_cfg_vap_not_running_misses` miss counter behind it are admin-owned
trust keys (prev-or-delete, the `blocked_sta_sha` shape: a device body can
neither introduce, forge, nor clear them). §6.5 emission semantics are
unchanged: the armed flag is still consumed by the device's next decoded
inform, one-shot, with no cfgversion minted at arming or emission.
Operator caveat: any admin save that mints a fresh cfgversion re-arms the
one-shot budget while the vap gap persists — one reboot per save (each
arm still separated by a delivered reboot and a genuine RUN proof).

### 6.6 `setdefault`
Factory reset path (device state 8): `return new Object("setdefault");` (line 1018).
Two-phase adoption (`o00000(string, device, x, …)` §902-924) stages:
1. `forObject` — mark phase‑1 done: returns `null` → HTTP write skipped (device
   completes quietly, then re-informs).
2. `o00000(...)` — mgmt refresh before upgrade: `new Object("setparam"){mgmt_cfg}`;
   if device ready: `o00000(device, fwState, ...)` → `upgrade {version,url,…}`.
3. EOL path: `\u300000000(device)` — removes device from DB (no body write).

**open-unifi (2026-09-19 lifecycle lane).** Implemented. DEVIATION from the
jar's arming shape: the classic controller arms factory reset as device
STATE 8, a controller-side enum member this store deliberately lacks
(adding one would redesign the pending-candidate lifecycle this lane
reuses), so arming rides the admin-owned Extra flag `setdefault_armed`,
set only by `POST /api/v1/devices/{mac}/factory-reset`. The device's NEXT
decoded inform answers exactly
`{"_type":"setdefault","server_time_in_utc":"<ms>"}` (the bare §6.6 shape
plus the §5 universal timestamp), and at emission the record returns to
the pending-candidate shape: state → pending, per-device key dropped,
cfgversion + applied cfgversion cleared, authkey history cleared, and the
controller-owned WLAN bookkeeping (`wlan_cfg_sha` & co., §6.2's drift
baseline) deleted — a stale baseline would let the re-adopted device
settle into connected noops while running factory config. The factory-reset
device re-informs on the factory default key and is re-adopted by the
existing §8 rotation path (§6.2 a/c/f mgmt_cfg-only family) unchanged.
No cfgversion is minted at arming or emission (no §6.2 setdefault site).
Precedence mirrors the dispatcher's layout: the state-8 check (§1018)
precedes every §6.2 setparam site (§1117+) and the §11006+ key gate, so an
armed setdefault outranks a simultaneously armed reboot and fires even on
a default-key inform.
Unrecoverable from the decompile (live-proof obligations): whether the real
controller clears `x_authkey` at emission or keeps state 8 until the
re-inform (our demotion happens at emission, one decision earlier); the
jar's post-setdefault record mutation beyond the response itself; the
armed-flag retention semantics across controller restarts; and the §6.5
dropped-response case — the flag is consumed in the emission decision, so
a failed seal or a dropped socket silently loses the factory reset (same
open questions as §6.5).

### 6.7 HTTP-status-only answers
404 unknown MAC, 400 decrypt/parse/"Bad packet magic"/"Data version %d is not
supported", 408 incomplete inform (EOF during body read), 503 controller-not-ready
(`service()` early return when status.returnnull()). No body in these cases.

## 7. SSH / TLS adoption channel (completes §6 of PROTOCOL.md)

Discovered-via-L2 devices are adopted out-of-band (voidsuper §2849-2861):

```java
if ("inform".equals(device.discovered_via) || device.isUDM()) { skip; }     // L3 inform only
int port   = device.getInt("sshd_port", 22);            // = discovery TLV 28
String url = config.L.\u300000000(device);               // the inform URL string
if (device.supportsSsh()) this.voidnullnew.o00000(mac, type, ip, port, user, pass, url, x_authkey, ssh_hostkey);
else                      this.oo\u00d4000.o00000(mac, type, ip, port, user, pass, url, x_authkey, ssh_hostkey);
```

- SSH runner `devmgr/privatesuper` (sshj): password auth with site mgmt
  `x_ssh_password` (default `ubnt`) and executes
  `/usr/bin/syswrapper.sh set-adopt <url> <authkey> [mac?]` (+` mac` appended when
  `supersuper.\u00f8\u00d60000()` — controller-hosted build) — `_Oo.o00000()` §347-363;
  host key pre-seeded from discovery TLV-16 fingerprint (`ssh_key`), else
  accept-all + discovery record update (`cfr_renamed_3("adopt", mac, result)` in
  voidsuper §3165-3215 stores `adopt_ip`, `x_adopt_username`, `x_adopt_password`,
  `adopt_url`, `x_ssh_hostkey(_fingerprint)`, sets adopt state 1, or errors
  `unreachable→2`, `loginfail→3`, `ssh_fingerprint→4` on `rc=error`).
- TLS runner `devmgr/ooOo` connects **TCP port 2022** (device-managed
  `mca-adopt` TLS) and streams the job JSON directly:
  ```java
  {"type":"adopt","mac":…,"device_type":…"type-name","ip":…,"port":2022*,
   "username":…,"password":…,"url":"<inform url>","authkey":"<32hex>","key":"<hostkey>"}
  ```
  (`*` port field always 2022 in code; result is parsed as JSON reply from device
  with `rc` / `ssh_key_new` / `ssh_fingerprint_new`, voidsuper §3150-3163.)

`checkreachable` is the SSH-only variant (`_OOo`, always port 22, no command).
`upgrade` task and `reboot` and `setdefault` (restore-default) reuse the same
`devmgr/privatesuper` helpers.

## 8. `Object(0x00)` / pending-adopt "initial_authkey" — default key logic

- Request decrypt trial list is `device.authkeys` (device record field), built as
  `[device.x_authkey, defaultkey-for-unknown]` (voidsuper §1969-1985: literal
  `"ba86f2bbe107c7c57eb5f2690775c712"`).
- After decrypt, magic strings in the payload are checked
  (`x.getString("_authkey")`); when default-key is still in use the code emits
  `[device authkey] send non-default authkey` and rotates `x_authkey` then pushes
  `setparam{mgmt_cfg}` (with `authkey=` line) on that same response path.

## 9. UNRESOLVED in this doc

- Precise `wireless.<n>.…` key-by-key listing inside `cfr_renamed_1(builder, device,
  …)` for AP beans exists in `config_int.java` but was not reproduced key-for-key
  (the Go builder for the MVP only needs: `users.1/2`, `sshd.*`, `bridge`,
  `netconf`, and the custom `config.system_cfg.<idx>` pass-through lines).
- `X.serialize(Object, boolean)` second parameter semantics (assume compact JSON;
  CFR shows `serializeTo(Writer, true)` calls in both paths).
- `unifi.cfgcap_info` bitmask meaning (int §2106-2120 helper) — corresponds to
  device *capability* check list, needed only if we choose to fake the mgmt_cfg
  capability list per-model.
- Device-side interpretation (`syswrapper.sh set-adopt` / what exact file the device
  writes (`/etc/init.d/… unifi config`)) is firmware behavior, not present in
  ace.jar.
- `users.1.password` transform: the hashing helper class (referenced from
  `config_String.java` as `com/ubnt/service/system/whilesuper`) is not yet
  decompiled. The current open-unifi implementation is per-device and uses the
  renderer's crypt/cache behavior; it does not emit a plain hex SHA-512 of a
  site-wide password. The plain-hex statement was a stale CURRENT claim. The
  jar observations above are historical evidence only; see
  `PROTOCOL-systemcfg-wireless.md` §10 for the current divergence.
