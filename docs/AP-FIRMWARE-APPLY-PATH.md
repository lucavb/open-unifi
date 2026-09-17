# AP firmware apply path — reverse-engineering record

**Scope:** how a UAP-AC-Pro-Gen2 (U7PG2, fw 6.8.2.15592) receives, validates and
applies the `system_cfg`/`mgmt_cfg` payloads a controller pushes in the inform
response — reconstructed from the AP's own binaries via Ghidra, cross-checked
against live behavior (2026-09-16) and against the original controller's
decompiled config builder (javap, `tmpwork/javap/`).

**Why this exists:** our generated `system_cfg` pushes were rejected live with
`[apply-config] Unable to write system.cfg or its contents are invalid.` while
`mgmt_cfg` pushes applied. The root cause (missing `netconf.1.status` in the
emitted schema) and the full acceptance chain are documented here.

## 1. Evidence base

| artifact | sha256 | notes |
|---|---|---|
| `/usr/bin/mcad` (AP) | `9fd76bec102de344aeb58c0fa49c4e370a1592e6ebf39ef66da12a427c2b6f59` | 230 229 B; copied to `T/opencode/u7pg2-mcad`; Ghidra program `u7pg2-mcad` (MIPS:BE:32, 1782 functions) |
| `/sbin/ubntbox` (AP) | `ecc8f55863b68c3e64b3aa796986a60b88cee21a0cedc9978f218e7c769c9290` | 2 808 524 B; copied to `T/opencode/u7pg2-ubntbox`; Ghidra program `u7pg2-ubntbox` (6434 functions) |
| `/sbin/stahtd`, `/sbin/ubntconf` | identical to ubntbox | applet symlinks into the same multi-call binary |

Ghidra project: `/home/admin/open-unifi/ghidra` (local instance, TCP
8089). All mcad functions below were renamed, plate-commented, tagged
`ap-apply-path` and saved in the program. `libubnt.so.1` / `libc2lib-1.4.2.so.1`
were NOT copied off the AP — parse() internals are inferred from call sites and
ubntbox's cfgmtd/ubntconf code, not directly disassembled.

## 2. mcad: inform response dispatch chain

Entry: `mcad_reporter_handle_response_json` (0x00414acc) — identity proven by the
`reporter_handle_response_json` string at 0x00430174 (49 xrefs, all from this
function) and the `ace_reporter.reporter_handle_response_json` log prefix.
It loads the response JSON (`json_load_file`) and then, in order:

| # | step | functions | behavior |
|---|---|---|---|
| 1 | `mgmt_cfg` | `mcad_extract_write_str_file` (0x0040aa90) → `mcad_write_file_validated` (0x0040a97c, flag=0) | RAW write to `/tmp/setmgmt.cfg`, **no validation**; then `parse("/tmp/setmgmt.cfg")` extracts `stun_url`, `mgmt_url`, `mgmt_authkey`, `cfgversion` (echoed to controller), etc. |
| 2 | `blocked_sta` | same helpers | raw write `/tmp/blocked_sta` + `syswrapper_impl(1, "apply-blocked-sta", 0)` |
| 3 | `system_cfg` | `mcad_extract_write_system_cfg` (0x0040aaa8) → `mcad_write_file_validated` (flag=1) → `mcad_validate_system_cfg` (0x0040a924) | VALIDATED write to `/tmp/system.cfg` (see §3) |
| 4 | on step-3 failure | `mcad_persist_response_json_file` (0x0040aa3c) | `json_dumps` (pretty) → RAW write to `/etc/persistent/bad-response.json` |
| 5 | on step-3 success | — | write `/var/run/mcad.setparam`; log `[setparam] applying new system.cfg`; `syswrapper_impl(1, "apply-config", "/tmp/system.cfg", 0)` |

`mcad_write_file_validated(content, path, flag)`:
NULL args → 0; writes content to `<path>.tmp` (fopen/fwrite/fclose); if
`flag != 0` the tmp file must pass `mcad_validate_system_cfg` before
`rename()`; failure → `unlink(tmp)` and return `-1` (flag≠0) or `0` (flag=0);
success → 1.

## 3. The system_cfg validator gate

`mcad_validate_system_cfg` (0x0040a924) accepts a staged file ONLY if:

1. `parse()` (imported from `libubnt`) parses it, AND
2. the parsed tree contains ALL three keys:
   * `users.1.status`
   * `netconf.1.status`
   * `sshd.status`

Any missing key ⇒ rejection. This is a hard firmware gate on EVERY `system_cfg`
push; there is no bypass and the failure log
(`[apply-config] Unable to write system.cfg or its contents are invalid.`)
points at neither the missing key nor the validator.

**Live confirmation (2026-09-16):** our generator never emitted
`netconf.1.status` (`git log -S "netconf.1.status"` → empty across all history);
every `system_cfg` push was rejected with exactly the log line above while
`mgmt_cfg` applied — precisely what the flag=1/flag=0 asymmetry predicts.

## 4. What the real controller emits for `# netconf`

`com/ubnt/service/config/String` (javap offsets 4694-4764; also
`config/OOoO` 1291-1400 — two independent writers agree): per netconf-inventory
instance (instance skipped when its `name` is null; single shared counter):

```
netconf.<n>.status=enabled        # literal, ALWAYS, FIRST row
netconf.<n>.devname=<name>
netconf.<n>.ip=<ip or "0.0.0.0">  # getString("ip", "0.0.0.0")
netconf.<n>.autoip.status=disabled
netconf.<n>.netmask=<null-filtered>
netconf.<n>.promisc=<null-filtered>   # plain getString("promisc")
netconf.<n>.up=<up or "enabled">
```

`netconf.1` is the management netconf (br0): the controller echoes the AP's own
reported inventory. ip `0.0.0.0` + `promisc=enabled` is the promiscuous-bridge
shape that asserts no addressing. See PROTOCOL-systemcfg-wireless.md §6/§7/§11.

## 5. `/etc/persistent/bad-response.json` — forensics semantics

Dumped on every system_cfg validation failure via `json_dumps` +
`mcad_write_file_validated(..., flag=0)`. Because it is RE-SERIALIZED
(pretty-printed), its bytes are NOT the original response payload: parse errors
found in derived artifacts are not evidence about the controller's response
encoding. Fetch this file from the AP when reproducing rejections — it contains
the exact rejected response.

## 6. After the gate: apply-config (ubntbox RE, confirmed)

On acceptance mcad calls `syswrapper_impl(1, "apply-config", "/tmp/system.cfg", 0)`.
The literal "apply-config" does NOT exist in ubntbox — the handler is the
on-device shell script `/usr/bin/syswrapper.sh` (not in our binary copies;
morning fetch list), which drives the ubntbox applets:

* **ubntconf** (`ubntbox_ubntconf_main`, 0x0045d45c; getopt `bc:p:o:s:hd:i:vmt`;
  default cfg `/tmp/system.cfg` @ 0x0063291c): stat checks — regular file
  (`(st_mode & 0xf100) != 0x8100` → `ERROR: ubntconf: Invalid cfg file '%s'`,
  exit 1; prev file: exit 2), `st_size < 100` reject, output dir S_IFDIR,
  startup list S_IFREG (exits 3/4). Then libubnt `parse()` → reads
  `unifi.cfgcap_info` (get_uint32) and `%s.status` (get_bool) for the **54
  `system.*` plugin registry** (0x00650094, 9-word descriptors, 0x36 entries) →
  runs the on-device plugin scripts + `/etc/startup.list`. Fast-apply diff path:
  `. /usr/share/ubntconf/plugin.funcs`, `IS_UBNTCONF_FAST_APPLY=true`,
  FAST_KILL_LIST `killall` loop, awk-dedupe of `/etc/inittab` vs
  `/tmp/.tmp_inittab`, `init -q`; persistent diff cache
  `/tmp/diff_%Y%m%d%H%M%S.cfg`. **This is where users/authorized_keys state
  materializes on apply** — the plugin scripts are on-device files, not in the
  binary.
* **cfgmtd** (`ubntbox_cfgmtd_main`, 0x004a4824; getopt `f:p:t:o:rwhcn`): NOT a
  parser — a **PACKER**: cfg text + 8-byte marker `0xBADC0DED`×2 (`DAT_006326f0`)
  + optional `tar -cz -O -C %s persistent` blob → zlib `compress` → MTD write
  with a 24-byte header `{magic 0x12345678 (BE), type 1|2, compressed_sz, crc32,
  orig_sz}` (at buf+6); 3-slot Active/Backup rotation (writer 0x0045eb50,
  reader/validator 0x0044f63c). Its `Invalid cfg file '%s'` is a stat check only
  (regular file, `st_size < 0x40` reject); it never parses the text. `-w` packs
  cfg+persistent into MTD, `-c` checks slots, `-r` extracts, `-f` defaults to
  `/tmp/system.cfg`.
* The literal `cfgmtd -w -p /etc /tmp/system.cfg` (0x00646944) belongs to
  **fwupdate.real** (const table 0x0049c150, canaries 0x01234567/0x28121969/
  0xfee1dead, refs 0x00499c54/0x00499d84 in the fwupdate main region 0x00499db8) —
  firmware-update-triggered persistence, NOT the apply-config path.
* Reverse direction: ubntbox also imports `syswrapper_impl`
  (`ubntbox_wevent_dispatch`, 0x0047ae14 — issues `ip-changed`,
  `mca-custom-alert`, `dump-radar-log`).

⇒ **The only text grammar that matters is libubnt `parse()`** — the same
parse() mcad's validator (§3) runs; cfgmtd/ubntconf add only stat-level checks
(regular file, ≥64/≥100 B). Real-builder-shaped configs pass by construction;
the mcad validator's three required keys were the only live failure.

## 7. Related applets (same ubntbox binary)

* `sysmon` — applet table entry #8 (`sysmon` → handler 0x0047a16c, MIPS16, stored
  as 0x0047a16d with the mode bit) and #9 `sysmon_ctrl` → 0x0047c61c. Option table
  0x0047a330: `-c` default `/tmp/system.cfg` (0x0063291c), getopt `c:dht:v`,
  usage "-t Shared poll time / -c System.cfg to use / -v verbosity",
  `/var/run/sysmon_uds_server`, handler-name strings `sysmon_main`/
  `sysmon_ctrl_init`/`sysmon_control_main` (0x0063aefc/0x0063af08/0x0063af40).
  Reads `system.monitor.%s.status/.threshold/.poll_interval`
  (0x00639ba4/0x00639700/0x00639838) — a read-only cfg consumer listening on the
  UDS for sysmon_ctrl. Supporting payloads mapped:
  `ubntbox_sysmon_uds_event_json` (0x0047cbd4, JSON connect/assoc/probe events
  over UDS) and `ubntbox_stahtd_assoc_success_payload` (0x0047d7f4). The main
  bodies are MIPS16 in an unreferenced region — function objects created there
  disassemble as MIPS32 garbage, so they were removed again; a real decompile
  needs a MIPS16 TMode-context disassembly pass (see §8.5).
* `trace` — standalone diagnostic injector: `trace_main` at 0x004903d0
  (**microMIPS** — the applet-table slot 0x00646aec stores fn=0x004903d1 with
  the ISA bit; not decodable with the default MIPS:BE:32 language — the plate
  comment there carries the reconstruction). Usage
  `[-n namespace] [-t type] [-T meta type] [json_payload]`, getopt `n:t:T:dv`;
  parses the POSITIONAL argv payload with jansson (`libjansson.so.4`,
  `json_loads`) and on failure logs `Failed to parse payload: %s at line %d,
  column %d)` (fmt at 0x00641810 — the stray `)` is a source typo matching the
  live log; the earlier claim that 0x00490534 "references" these strings was a
  misread: 0x00490514-0x0049053c is trace_main's microMIPS PC-relative literal
  pool). Success path injects the trace into sysmon via the shared trace API
  (`trace_object*`, `send_trace_simple`, `send_trace_with_meta`) over
  `/var/run/sysmon_uds_server`. There is NO in-binary caller — payloads come
  from external CLI invocations only. Applet dispatch:
  `ubntbox_dispatch_main` (0x00447b80): basename(argv[0]); `ubntbox` means
  applet=argv[1], otherwise the basename IS the applet (symlinks work);
  23-entry table at 0x00646ab0 ({name, fn, flag} × 12 B): ubntconf, cfgmtd,
  fwupdate.real, factorytest, nettool, trace, coredump, sysmon, sysmon_ctrl,
  egtool, hwcheck, ubootenv, bgnd, vwirectl, wevent, utermd, pll, oopsdump,
  ubntevent, ubnt-netmon, stahtd, verifypackages, selfupgrade.
* `wevent` — `ubntbox_wevent_dispatch` (0x0047ae14) issues syswrapper events.

## 8. Open questions

1. **`trace_main(): Failed to parse payload: invalid escape at line 10, column 409`**
   (live, right at a rejected push) — **RESOLVED (2026-09-16): NOT caused by
   mcad or our provisioning.** mcad's only trace sender is
   `mcad_send_inform_timeout_trace` (0x00408274 → `send_trace_simple` PLT
   0x004352f0, imported from a shared lib; namespace
   `unifi:network:firmware:event`, type `anomaly`): its payload is built
   entirely with jansson (`json_object`/`json_string`/`json_integer`), never
   serialized to a string, and mcad never execs the trace CLI (no `ubntbox`
   string in the binary) — it cannot produce a parse error. The reporter's
   rejection path (`bad-response.json`) makes zero trace calls. The error comes
   from the standalone `ubntbox trace` CLI (§7): its POSITIONAL argv payload was
   a hand-assembled multi-line JSON with an unescaped backslash ("line 10" /
   "column 409" is the fingerprint of string-concatenated JSON — conforming
   encoders, incl. Go `encoding/json` and jansson `json_dumps`, cannot emit
   invalid escapes). The caller is external to both binaries (script/plugin/
   diagnostic); temporal coincidence with our rejected push is most likely
   just that (~0.55). Confirm on-AP per §10.7.
2. **SSH-key wipes during rejected full-provisioning pushes**: mcad contains NO
   `authorized_keys` handling; `users.1.*` rows are consumed only by mcad's
   validator, and `mcad_reporter_reload` (0x00412c24) reads `sshd.status` from
   the CURRENT `/tmp/system.cfg` merely as the runtime sshd flag. The users/keys
   materialization is the ubntconf plugin-script layer (§6). Since our pushes
   never passed the validator, `/tmp/system.cfg` on the AP retains its
   PRE-provisioning content — any reapply of it (reboot, ubntconf run, mgmt_cfg
   side effects) rebuilds users state from config rows and wipes a key installed
   out-of-band. To confirm: fetch `/usr/bin/syswrapper.sh`,
   `/usr/share/ubntconf/`, `/etc/startup.list`, a `/tmp/system.cfg` snapshot and
   logs from the AP.
3. **libubnt `parse()` grammar internals** — the ONLY text grammar in the chain
   (cfgmtd never parses: it is a stat-checking MTD packer, §6). Not disassembled
   (lib not copied off the AP). Low residual risk: real-builder-shaped configs
   (incl. `# section` comment headers) are proven accepted — the factory config
   itself parses and the mcad gate uses the same parse().
4. **fwupdate.real's table loader** — which function in the MIPS16 region at
   0x00499db8+ loads the const table 0x0049c150. Minor; addresses documented.
5. **sysmon/sysmon_ctrl main bodies** — MIPS16, unreferenced region (§7); need a
   TMode-context disassembly pass for a real decompile.
6. **Authoritative compatible controller version for fw 6.8.2.15592** — still
   inferred, not authoritatively established.

## 9. Generator impact

* `internal/server/wireless.go` (`emitVlanBlocks`/`emitNetconfSection`): always
  emit `netconf.1` (mgmt) with `status=enabled` first; VLAN instances contiguous
  from 2, each with its `status` row. U7PG2 stays fail-closed until live
  validation passes (see docs/WLAN-ACCEPTANCE-6.8.2.15592.md).
* `users.1.status` and `sshd.status` rows were already emitted
  (server.go ~1439/~1457) — the netconf row was the only missing gate key.

## 10. Morning AP fetch list (needs ssh access restored)

1. `/usr/bin/syswrapper.sh` — the actual `apply-config` dispatcher (not present
   in any copied binary).
2. `/usr/share/ubntconf/plugin.funcs` + the `system.*` plugin scripts +
   `/etc/startup.list` — the users/authorized_keys materialization layer.
3. `/etc/persistent/bad-response.json` — the exact rejected-response dump (§5).
4. `/tmp/system.cfg` snapshot — what the AP actually holds now (pre-provisioning
   content, per §8.2).
5. `libubnt.so.1` + `libc2lib-1.4.2.so.1` — the parse() grammar, for completeness.
6. Stray `stahtd` process check (hygiene; a bare stahtd may have been left
   running during the applet-help loop).
7. Trace-mystery confirmation (§8.1): scripts containing `trace -n`/`trace -t`
   under `/etc/persistent`, `/usr/share/ubntconf/`, controller-pushed packages;
   `/var/log/messages` timestamps around the `trace_main()` line vs the mcad
   rejection and `bad-response.json` mtime; `ldd /sbin/mcad` to resolve which
   shared lib provides `send_trace_simple`.

*(Recorded 2026-09-16 from the overnight RE session; Ghidra annotations live in
the `ghidra` project, plate comments carry the per-function evidence.)*
