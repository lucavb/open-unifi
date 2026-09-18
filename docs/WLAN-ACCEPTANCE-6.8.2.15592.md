# Live WLAN acceptance evidence template

This remains a pending evidence template, not an acceptance claim. Live WLAN
provisioning is gated by default (the fail-closed runtime gate rejects any
managed WLAN for U7PG2 6.8.2.15592 with a typed 501); the gate lifts only by
the explicit lab opt-in `--allow-gated-live-wlan`, and end-user acceptance
still requires the matrix below.

This is a repeatable, firmware-specific acceptance record for a
**UAP-AC-Pro-Gen2 (`U7PG2`) running firmware `6.8.2.15592`**. Copy this file
for each run and fill in the evidence fields. It is a record template, not a
test result: an unchecked or `NOT RUN` item must not be described as passed.

## Scope and status vocabulary

The protocol evidence currently in the repository is separate from proof that
an end-user client can use a WLAN. The live controller evidence in
[`PROTOCOL.md`](PROTOCOL.md) proves adoption, key rotation, provisioning,
WLAN configuration push, and steady-state informs for the identified AP. It
does **not** by itself prove client association, DHCP, forwarding, tagged
VLAN handling, or recovery after each destructive operation.

Use exactly one status for every case:

- `PROVEN` — performed in this run and all stated observations have evidence
  references.
- `FAILED` — performed, with the failure and evidence recorded.
- `BLOCKED` — attempted but prevented by an environment or safety condition;
  record the condition.
- `NOT RUN` — not performed. Do not infer a result from another case.

The release claim remains gated until the required end-user cases below have
run on the target firmware and their evidence has been reviewed.

## Current proven protocol evidence (not end-user WLAN evidence)

The following is the current repository record and must remain distinct from
the matrix below:

- Device: UAP-AC-Pro-Gen2 / U7PG2
- Firmware: 6.8.2.15592 (`BZ.qca956x_6.8.2+15592.260126.1358`)
- Date: 2026-09-16
- Proven observations: factory discovery parsing, adoption push using the
  factory key, per-device key rotation and re-inform, full provisioning,
  WLAN configuration push with AP `vap_table` reporting `RUN`, restart-time
  full `system_cfg` push with matching `cfg`, and steady-state noops.
- Evidence: controller log and full session capture, as referenced by
  [`PROTOCOL.md` §7](PROTOCOL.md#7-carry-list--closed-by-live-acceptance-2026-09-16).
- End-user status: **not established by that record**. Association, DHCP,
  traffic forwarding, 802.1Q observation, configuration mutation behavior,
  VAP disappearance, multi-WLAN/radio coverage, lost/recovery, and
  factory-reset/re-adoption cases remain independently gated here.

## Run identity and safety record

Fill these fields before testing. Never put credentials or secret material in
this document or in referenced artifacts.

| Field | Value |
| --- | --- |
| Acceptance run ID | `________________` |
| Date/time started (UTC) | `________________` |
| Date/time completed (UTC) | `________________` |
| Operator / reviewer | `________________` |
| AP model / hardware | `UAP-AC-Pro-Gen2 / U7PG2` |
| AP firmware exact string | `6.8.2.15592 / ________________` |
| AP MAC (redacted form) | `XX:XX:XX:XX:__:__` |
| Controller commit/build | `________________` |
| Controller config/data identifier (hash only) | `________________` |
| Switch/router model and firmware | `________________` |
| AP switch port / trunk mode | `________________` |
| Test client OS/version | `________________` |
| Test client interface MAC (redacted form) | `XX:XX:XX:XX:__:__` |
| Test VLAN IDs / subnet labels | `________________` |
| DHCP server/scope label (not secret) | `________________` |
| Capture/log storage location | `________________` |
| Safety backup and restore confirmed | `YES / NO / N/A` |

### Redaction and safety rules

- Do not record WLAN passphrases, admin/API tokens, AP SSH passwords,
  `x_authkey` values, private keys, cookies, Authorization headers, Terraform
  state, or unredacted configuration/data files.
- Before attaching logs or packet captures, remove credentials and payloads
  that contain them. Preserve timestamps, direction, protocol flags, message
  types, status codes, VLAN tags, and hashes where they are needed to prove a
  result.
- Use synthetic SSIDs and test-only VLANs. Record an SSID as a label or
  hash, never a production SSID if it identifies a site. Record only
  passphrase policy (`set`, `changed`, `cleared`), never the passphrase.
- Redact public IPs, hostnames, client identifiers, and MAC octets as needed
  while retaining stable per-run aliases such as `AP-1`, `CLIENT-1`, and
  `SWITCH-PORT-1`.
- Confirm that destructive actions (WLAN deletion, AP deletion, factory
  reset) have an approved rollback and do not affect production WLANs.

## Exact evidence fields

Complete these fields for every matrix row, including `NOT RUN` rows:

```text
Case ID / title:
Status: PROVEN | FAILED | BLOCKED | NOT RUN
Run ID:
Start/end (UTC):
AP alias / firmware:
Controller build / config hash:
Switch port / AP radio(s):
WLAN label / SSID hash:
Security mode / VLAN ID:
Client alias / OS:
Expected result:
Action transcript (commands/UI action, with secrets omitted):
Observed controller state:
Observed AP state:
Observed client state (association, IP, gateway, DNS):
Observed network result (DHCP, traffic, isolation/forwarding):
Observed wire result (capture interface, direction, 802.1Q VID/PCP):
Start/end evidence timestamps (UTC):
Evidence references (log/capture/photo/hash, redacted):
Failure or deviation:
Operator initials:
Reviewer / review date:
```

For a `NOT RUN` row, fill the identity fields that are known, set the reason
in `Failure or deviation`, and leave the observation fields explicitly
`NOT RUN` rather than guessing.

## Acceptance matrix

The cases are intentionally explicit so that a protocol-only result cannot be
substituted for an end-user result. Repeat the relevant cases for each test
SSID and each intended radio where the row says `2.4 GHz` or `5 GHz`.

| ID | Required case and pass criteria | Status | Evidence refs |
| --- | --- | --- | --- |
| A1 | **Factory adoption:** factory AP is discovered/adopted; AP reports adopted/connected; controller records the expected model and firmware; post-adoption inform is received. | `PROVEN` | §2026-09-18 F-row live round — adoption chain 07:32:47–07:34:09Z (adoption-seed engine finding recorded there); §2026-09-18 verify round — re-proven under the fixed engine, adoption delivers the envelope automatically 11:21:45–11:23:13Z |
| A2 | **Restart with retained key:** adopted AP is restarted without deleting controller state; it re-informs using the retained key, returns to connected, and receives/retains the expected configuration. | `FAILED` | §2026-09-18 F-row live round — 74 s gap + retained-key re-inform + cfg echo unchanged proven 08:09–08:12Z; applied config did NOT survive the reboot (recovery via the tested self-heal remedy); §2026-09-18 verify round — retention failure re-confirmed (factory vap + matching cfg echo on the first re-inform) and automatic watchdog recovery live-proven 11:29:59–11:30:48Z, unattended; §2026-09-19 root cause resolved — the renderer's `mgmt.is_default=true` factory-echo row tripped the AP preinit boot guard (`/lib/preinit/99_21_ubnt_ubntconf` replaces the MTD-restored text containing it with the factory template; docs/AP-FIRMWARE-APPLY-PATH.md §6.5); fix in render.go, re-run pending |
| B1 | **WPA-Personal association:** WPA-Personal test client associates to the intended SSID on 2.4 GHz and 5 GHz as applicable; client receives DHCP lease and can pass the defined allowed traffic test. | `NOT RUN` | `________________` |
| B2 | **Open association:** open test client associates; client receives DHCP lease and can pass the defined allowed traffic test. | `NOT RUN` | `________________` |
| B3 | **Tagged VLAN:** WPA-Personal and/or open test WLAN configured with a tagged VLAN; client associates and receives DHCP on the intended subnet; traffic passes; capture on the AP uplink visibly records 802.1Q with the expected VID (or records the exact reason the observation point cannot see the tag). | `NOT RUN` | `________________` |
| C1 | **SSID/passphrase/VLAN update:** change the SSID, passphrase, and VLAN; old credentials/SSID no longer work as expected, new credentials associate, DHCP is from the new VLAN, traffic passes, and AP/controller state reflects the update. | `NOT RUN` | `________________` |
| C2 | **WLAN deletion / VAP disappearance:** delete or disable a WLAN; controller config omits it, AP `vap_table`/equivalent no longer shows the VAP on each applicable radio, and the client can no longer associate to it. | `NOT RUN` | `________________` |
| C3 | **Bridge-apply survival (WLAN-count change):** change the WLAN count so the rendered bridge port list changes (e.g. remove the 5 GHz vap); the AP stays reachable through the apply (inform continues), br0 recovers its address and uplink, and remaining WLAN service recovers. If the AP darks, capture the failure with console access ready — the offline verdict predicts exactly that. | `NOT RUN` | offline: §Bridge-apply verdict; tmpwork/harness-20260917/night-deltas.txt |
| D1 | **Multiple WLANs on both radios:** configure at least two WLANs, with intended 2.4 GHz and 5 GHz coverage; each expected VAP is present, clients associate to each, receive the correct DHCP/VLAN result, and pass the defined traffic test. | `NOT RUN` | `________________` |
| E1 | **AP lost/recovery:** isolate or power off the AP; controller marks it lost within the documented window; restore connectivity/power; AP re-informs, returns connected, and WLAN client service recovers. | `NOT RUN` | `________________` |
| F1 | **Controller-side deletion:** delete the adopted AP/controller device record using the approved procedure; record resulting AP state and confirm the expected re-adoption path without claiming success unless completed. | `PROVEN` | §2026-09-18 F-row live round — deletion 07:25:55Z; decrypt-failure informs at escalated cadence; pending sourced from discovery announces; re-adoption completed under F2; §2026-09-18 verify round — re-proven under the fixed engine 11:14:39Z |
| F2 | **Factory reset, deletion, and re-adoption:** after approved backup, factory-reset the AP, verify it returns to factory state, remove/clean its old controller record as required, adopt it again, and repeat the minimum WLAN association/DHCP check. | `BLOCKED` | §2026-09-18 F-row live round — backup/reset/factory verify/re-adopt all proven 07:27–07:34Z; final association/DHCP check NOT RUN: no test client at the bench (same environment condition as the C1-shape round); §2026-09-18 verify round — full chain re-proven automatically under the fixed engine 11:17–11:23Z (mint → provisioning → byte-exact settle, no store surgery); client-side sub-criterion unchanged |

### Bridge-apply verdict (2026-09-17 night pass — offline plugin forensics; no live run)

Verdict: **same-shape pushes (security/SSID updates) are PUSH-SAFE by
invariant + gate; WLAN-count changes (the C2/C3 shape) are NOT PUSH-SAFE
— BLOCKED pending a live C3 run or a Ghidra pin of the apply
orchestration.** Evidence: the fetched factory plugin set
(`tmpwork/harness-20260917/ap-plugins/etc/sysinit/`, with
`ap-forensics/usr/share/ubntconf/plugin.funcs` + `etc/startup.list`) and
the successive-push gates
(`internal/server/zz_minimaldiff_scratch_test.go`, listings in
`tmpwork/harness-20260917/night-deltas.txt`).

- **Restart granularity**: `run_plugin()` sources `/etc/sysinit/<name>.conf`
  and calls `plugin_start`/`plugin_stop` (plugin.funcs:1-14); ubntconf
  fast-apply regenerates a section's plugin script from the parsed
  `system_cfg` rows and restarts it iff its parsed tree changes — including
  changes caused by row deletion (minimal-diff-spec.md:5;
  internal/server/server.go:1001-1017). The fetched `bridge.conf`/`net.conf`
  are the factory-rendered instances (hardcoded eth0/ath0/ath1,
  192.168.1.20 — matching the factory config's rows).
- **Bridge apply is destructive and IP-blind**: `bridge.conf plugin_stop`
  does `ifconfig br0 down` + `del-bridge-vlans` + `brctl delbr br0`
  (bridge.conf:33-41 — the ONLY `delbr` site in the fetched tree) + removes
  `vapbridge.*` + clears the nfbypass map. `plugin_start` only re-creates the
  bridge and re-adds the ports (bridge.conf:1-32); it carries **no
  ifconfig/IP bootstrap**. The only re-IP path in the tree is the `net`
  plugin's start (net.conf:6-13), which runs only when the `netconf` tree
  changes. Startup order: radio(7) wireless(8) … bridge(13) net(15)
  connectivity(17) route(18) dhcpc(19) aaa(20) (startup.list:1-33); the
  per-restart orchestration lives in `syswrapper.sh`, which is ABSENT from
  the copies (AP-FIRMWARE-APPLY-PATH.md:101-102,232 — morning-fetch item).
- **Distinct from the 2026-09-16 fatal mechanism**: those pushes darked via
  the `net` restart — our netconf carried one mgmt instance vs the running
  four, so net.conf stop took br0/eth0/ath* down and (fast-apply) killed
  dropbear, with the regenerated 1-instance net.conf never re-upping eth0
  (minimal-diff-spec.md:10-12; internal/server/wireless.go:477-490). The
  bridge-restart path is new: br0 is deleted and recreated **down and
  IP-less**, and with our netconf echo byte-identical the net plugin does
  not re-run, so nothing re-IPs br0. Recovery would require the inittab
  udhcpc respawn (dhcpc.conf:3) to rebind to the recreated br0 and lease —
  behavior unverified (udhcpc is bound to the old ifindex; whether it exits
  and respawns is not evidenced in the copies).
- **Per-candidate offline gate results** (vs the APPLIED baseline
  sha256 b25a2c80007f564c3331d98ce8b020e96321701785740e824fc4f29d0ca8235e,
  record seeded with its ssh_sha512passwd cache):
  - **Same-intent re-push** (both-band open): 0 intended, 0 violations —
    byte-identical, no plugin restarts at all.
  - **wpa-p both-band** (the C1 shape): 30 managed deltas confined to
    `aaa.1/2.*` wpa rows + `wireless.1/2.authmode`; netconf/connectivity/
    bridge/dhcpc/… byte-identical, 0 violations, no bridge rows. Restart
    set = {wireless, aaa} — both evidenced survivable on the accepted
    2026-09-17 push. **PUSH-SAFE by invariant + gate** (still subject to
    live B1/B2).
  - **2g-only** (the C2 shape): 46 managed deltas (5g vap rows dropped)
    + exactly one unmanaged delta — `bridge.1.port.3.devname` removal,
    i.e. the bridge tree changes. Restart set = {wireless, aaa, radio,
    bridge}; the first three are evidenced survivable (managed sections;
    radio + wireless + aaa all restarted on the accepted push), but the
    bridge restart deletes br0 with the IP-blind gap above. **NOT
    PUSH-SAFE; do not push a WLAN-count change to the live AP until C3
    runs on the bench with console access, or the apply orchestration is
    pinned in Ghidra (u7pg2-ubntbox) showing a re-IP path.**
- **Real-controller parity note**: WLAN-count changes alter the real
  builder's bridge ports as well (PROTOCOL-systemcfg-wireless.md §2.1 —
  the real collector synthesizes per-radio mesh vaps, so its port list
  moves with every WLAN edit). Whether the real controller's own pushes
  co-change netconf on WLAN-count edits (its netconf per-iface instances
  may track vap devnames — factory netconf.4.devname=ath1 named the vport
  vap) and thereby re-IP br0 via the net restart is UNVERIFIED; that is
  the morning bytecode question behind C3's BLOCK.

#### ubntbox fast-apply registry (2026-09-17 night Ghidra addendum)

The night Ghidra pass over `u7pg2-ubntbox` pinned the fast-apply engine
itself (corrections and refinements to the model above — the BLOCK
verdict stands):

- **In-binary plugin registry** at 0x650094: 54 entries × 36-byte
  descriptors `[name, ?, deps, flags, ?, fn, ?, handler, ?]`
  (big-endian). Located entries: system=e0 (slot 0x650094), users=e2
  (0x6500dc), wireless=e8 (0x6501b4, flags 0x48, handler 0x0048ED29),
  **bridge=e15 (0x6502b0: name "bridge"@0x6406FC, deps=NULL, flags=0,
  in-binary handler 0x004AB1B9)**, **netconf=e17 (0x6502f8: flags=0x20,
  handler 0x00487345, deps list @0x6b9ce4)**, unifi=e44 (0x6506c4).
  The net plugin is named **netconf** in the registry.
- **Runner** (0x004B1B94): for a changed plugin it first runs each
  dependency plugin recursively (dep name strings resolve via
  0x0045E16C; "Invalid dependency"/"Fast dependency %s failed"), then
  builds the plugin's cfg_it as its own section PLUS each dependency's
  section appended (get_cfg_it "%s"), and only then calls the handler.
  `netconf`'s handler region references the "bridge" string
  (0x00487214) — the netconf fast path touches the bridge; a
  [netconf, bridge] dependency list exists at 0x6b9cd8.
- **Gatekeeper** (0x004B18F4): (a) no in-binary handler → `ERROR: %s:
  Unhandled fast apply for plugin` → fallback; (b) handler present but
  the new slice carries a truthy `<name>.status` row and the entry lacks
  flag 0x20 → `ERROR: %s: Unhandled status change` → fallback
  (decompile: `if ((flags & 0x20) != 0 || get_value(cfg, 0, "%s.status",
  name) == 0) return 1;` — the fast path runs only when the status row
  is absent/falsy). Every normal config carries `bridge.status=enabled`
  (PROTOCOL-systemcfg-wireless.md §12) and bridge has no 0x20
  exemption, so a bridge-section change is REFUSED the incremental
  in-binary path and takes the script-restart fallback — the
  delbr/IP-blind path of §Bridge-apply verdict. This is the refusal
  that makes the C3 BLOCK mechanical, not just script-forensic.
  Caveat: the exact get_value polarity is read from one decompile;
  the decisive test remains the live C3 run (or the handler bodies
  below).
- **Blocked residual**: the bridge fast handler body (0x4AB1B8, region
  ~0x4AACB0–0x4AB8B0, consumes `bridge.%d.devname/.fd/.stp.status/
  .port.%d.devname/.port.%d.prio` formats) and the netconf handler
  (0x487344) are **microMIPS** (odd function pointers; creating a
  function there disassembles MIPS32 garbage — the known sysmon
  problem, AP-FIRMWARE-APPLY-PATH.md §7). Decompiling them needs
  `GHIDRA_MCP_ALLOW_SCRIPTS=1` on the Ghidra host, then a TMode=1
  context script over the region (drafted in
  tmpwork/harness-20260917/NIGHT-REPORT.md). That decompile would
  confirm or refute the bridge refusal reading and reveal whether
  netconf's fast path re-IPs br0 — the recovery mechanism C3 needs.


### 2026-09-18 C1-shape live round (post-refactor; controller 296fb60b29cfa9cc)

Scope: redeploy the server-deepen-refactored build and prove the C1
SHAPE (security mutation, vap shape unchanged) live. This is NOT the
full C1 case: no test client was at the bench, so every client-side
criterion of B1/B2/C1 stays `NOT RUN`. Operator present with console
access; AP SSH open.

- **Pre-deploy**: `make check` on main had been broken by the refactor
  merge (the night gate test still called the pre-refactor helpers);
  fixed in `zz_minimaldiff_scratch_test.go` (`zzRecordFacts`). All five
  night gates reproduced their 2026-09-17 results in main's tree.
- **Deploy**: `openunifi.linux` sha256 `296fb60b29cfa9cc…` (rollback
  saved by ctl.sh). The AP re-informed 10 s after the swap with a GCM
  noop — the refactored inform codec and adoption engine live-validated
  on the retained-key steady state.
- **Finding — the night "APPLIED" baseline was never the pushed bytes**:
  `render-fixed-sys.txt` carries env id `7a5326f6…` =
  sha256("gate-check")[:24] (the `wireless.WlanID` name-only derivation)
  while the live envelope carries the admin API's sha256(name+ssid)[:24]
  stamp `2dab5684…` (internal/app/app.go:530), and its seeded
  `ssh_sha512passwd` was stale against the live record's cache. The
  confirmed 2026-09-17 19:17 CEST push rendered from the live envelope.
  The file remains the night regression gates' reference only; live
  rounds now use the rolling device-verified baseline
  (`live-applied-sys.txt`), enforced by `TestZZLiveIntentVsApplied`
  (steady state must be 0/0) and the candidate-gate template
  (`TestZZLiveWpaCandidateVsApplied`).
- **Runtime gate discovery**: the deployed build refused the push — the
  fail-closed live-WLAN gate (adoption engine, typed 501) had no unlock
  path. Added the explicit lab opt-in `--allow-gated-live-wlan`
  (`adoption.Deps.AllowGatedLiveWLAN`; fail-closed default preserved;
  wiring covered by `TestEncryptedGateLiftedByOptIn`); `scripts/ctl.sh`
  runs the bench with it.
- **Push (08:42:12–08:42:55 CEST)**: envelope mutated to wpa-p (id
  preserved); candidate gated at 30 deltas, all inside `{wireless, aaa}`;
  pushed bytes sha256 `9891d9ff…` proven on the wire (system_cfg
  diagnostic) AND on the device (`sha256sum /tmp/system.cfg` =
  `9891d9ff…`, `aaa.1/2.wpa=3`, `wpa.key.1.mgmt=WPA-PSK` present). One
  delivery retry fired on the previous-config echo (`dd0a…` → `d0ba…`);
  settle confirmed: vap_table shows both vaps RUN (ath0 ng ch 6, ath1 na
  ch 157), cfg echo `d0ba82ecdbfdccd6` == controller intent, `in_sync`
  true, steady ~15 s noops resumed. **The AP stayed reachable through
  the apply — the {wireless, aaa} restart-set survival prediction held
  live.** The round passphrase is synthetic bench material
  (`openunifi-fake-c1-psk-20260918`), recorded here as such.
- **Still open**: B1/B2/C1 client-side evidence (no client); C3 unchanged
  (`BLOCKED`, bench+console run or Ghidra microMIPS pin); release claim
  unchanged.

### 2026-09-18 F-row live round (adoption lifecycle; controller 296fb60b29cfa9cc)

Scope: close the controller-side lifecycle rows F1, F2, A1, the
provisioning byte-delta check, and A2 on the live bench. No test client
was at the bench, so every client-side criterion stays `NOT RUN`; operator
remote with AP SSH open (password lane via expect; operator key re-deployed
where noted below). All times UTC; controller log lines are +02:00.

- **Pre-round state**: repo main `dcee7c2` (module-path rename only,
  behavior-neutral — a deviation from the run brief's expected `7efd156`,
  recorded here); controller binary unchanged since the C1-shape round
  (`296fb60b29cfa9cc…`, no redeploy this round); approved backup
  `tmpwork/harness-20260917/f2-backup-20260918/pre-f2-snapshot-20260918.json`
  (device record + envelope + empty pending); wireless envelope untouched
  all round (id `2dab5684…`, wpa-p, the synthetic bench passphrase recorded
  in the C1-shape round).
- **F1 — controller-side deletion (07:25:55Z, PROVEN)**:
  `DELETE /api/v1/devices/<mac>` → `200 {"status":"deleted"}`; device list
  immediately empty; device GET → `404 device not found`. The AP kept
  informing every ~5.4 s (escalated from the ~15 s noop cadence), each
  attempt logging `inform: unregistered device` + `inform: no key produced
  a valid JSON payload` (`tried:1` — the factory-default key trial; the
  device's retained per-device key no longer matches any store record).
  Retained-key informs never surface in `/api/v1/pending`; the pending
  candidate that appears is sourced `discovery` from the live 10 s
  announces (`factory=false` — the AP still runs the pushed config and is
  merely unmanaged from the controller's view). AP state untouched:
  `/tmp/system.cfg` sha unchanged `9891d9ff…`, authorized_keys intact,
  `mca-cli-op info` → `Status: Connected (http://10.10.10.10:8080/inform)`.
  The expected re-adoption path was completed under F2 below.
- **F2a — factory reset (07:27:29–07:30:35Z)**: `syswrapper.sh
  restore-default` over SSH; the last retained-key inform arrived 07:27:33Z
  and informs then CEASED; the AP returned after ~2 min 17 s dark,
  re-leased 10.10.10.20 (bench DHCP by MAC; the 192.168.1.20 factory fallback
  is unreachable — no DHCP server on that segment); factory announces from
  07:29:36Z (`uptime=43`, `factory=true`, 10 s cadence). Factory state
  verified 07:30:35Z: `/etc/version` `BZ.6.8.2` unchanged; authorized_keys
  0 lines; `/tmp/system.cfg` byte-exact equal to the factory baseline
  `b1df1da2…` (178 lines, 0 gate-check rows); `mca-cli-op info` →
  `Status: Unable to resolve (http://unifi:8080/inform)` (the factory
  default inform URL). The controller listed the factory candidate in
  pending, sourced `discovery`.
- **Runbook finding — `mca-cli-op` syntax**: the one-shot form is
  `mca-cli-op <command> [args]` (`info`, `set-inform <url>` work);
  `--help` is treated as a command name (`--help: command not found`,
  rc=1); a bare invocation enters an interactive `UniFi#` CLI and hangs a
  non-tty — never run it bare from scripts.
- **F2b/A1 — set-inform + factory adoption (07:32:47–07:34:09Z, A1
  PROVEN)**: `set-inform http://10.10.10.10:8080/inform` → `Adoption request
  sent to 'http://10.10.10.10:8080/inform'`; informs resumed within seconds
  with no decrypt-failure lines (the factory default key decrypts);
  `POST /api/v1/pending/<mac>/adopt` 07:33:51Z → `200 {"state":1,
  "actions":["delete"]}`; 07:34:06Z inform flags `0x0003` → `inform:
  adoption push (default key)` → setparam reply `gcm:false` (mgmt_cfg
  only, fresh per-device key); 07:34:09Z re-inform flags `0x000b` (GCM,
  bodyLen 884) → `connected noop`, cfg echo `ad3e75e017acef1e` —
  per-device key rotation live-proven, no reboot; the record carries
  model `U7PG2`, firmware `6.8.2.15592`, IP, state 3, pending empty.
- **Finding — adoption seeds the drift baseline with the current intent
  hash (engine gap)**: the adoption push seeds `wlan_cfg_sha` with the
  CURRENT envelope hash (`internal/server/adoption/engine.go:367`), so a
  freshly adopted device never receives the pre-existing envelope — the
  drift check compares the intent hash against itself, and the device
  echoes the adoption cfgversion forever (`connected noop`, `in_sync`
  false, factory vap_table). The engine's own recovery for an ABSENT
  baseline (mint a fresh cfgversion, forcing exactly one full provisioning
  — `TestMissingBaselineForcesProvisioning`,
  `internal/server/server_test.go:1496`) is test-pinned but suppressed by
  the seed. The real controller delivers the envelope with adoption; the
  fix (seed after delivery proof, or seed empty at adoption) is recorded
  for the codebase — not changed this round. Bench remedy, user-approved:
  controller restart with the misseeded `wlan_cfg_sha` removed from the
  store record (data-only surgery, same binary; backups
  `devices.json.bak-20260918T075433Z` / `devices.json.bak2-20260918T081405Z`).
- **Provisioning verify (07:54:42–07:55:42Z)**: after the remedy the
  self-heal fired exactly as tested — `inform: no envelope baseline,
  forcing provisioning` (07:54:42Z) minted `db816c79fbc76642`; the next
  inform (07:54:55Z) mismatched → `inform: full provisioning` → setparam
  push. **Byte-exact delivery**: the system_cfg diagnostic sha256
  `6656ecc3…` equals the on-device `sha256sum /tmp/system.cfg` (bytes
  fetched base64 over SSH and re-hashed locally), and against the
  pre-round rolling baseline `9891d9ff…` the diff is EXACTLY ONE HUNK —
  `users.1.password` (fresh salt `$6$AB12CD34$` vs `$6$EF56GH78$`), the
  predicted single delta. No radio hunks: `radio.*.channel=0` in both
  configs; the differing runtime channels (ath0 ng ch1, ath1 na ch36/bw40
  this round vs ch6/ch157 in the C1 round) are firmware auto-picks.
  Settle: the 07:55:30Z re-inform echoes `db816c79…`, vap_table shows both
  vaps RUN with the envelope id, `in_sync` true, delivery `confirmed`
  (count 1). **The AP stayed reachable through the apply** — the
  factory→our-config transition restarts only managed sections
  (netconf/bridge/dhcpc byte-identical to factory, no IP-touching
  restart): the factory-echo invariant is now evidenced in both
  directions.
- **Side finding — authorized_keys is regenerated by any users-section
  apply**: a push that changes the `users.*` section (fresh password
  cache) regenerates `/etc/dropbear/authorized_keys` from the config,
  which carries no key rows — the operator's key is wiped by provisioning
  applies, not only by factory reset. The password lane (ubnt/ubnt via
  expect) stayed available throughout.
- **A2 — restart with retained key (08:09:17–08:12:27Z, FAILED on the
  retention criterion)**: reboot over SSH at 08:09:17Z; last inform
  08:09:15Z, first post-reboot announce 08:10:28Z (`uptime=43`), first
  inform 08:10:29Z — a **74-second inform gap**; the re-inform used the
  RETAINED per-device key (flags `0x000b`, GCM, no factory-key phase, no
  pending candidate, no re-adoption), returned to connected, and echoed
  the UNCHANGED cfgversion `db816c79fbc76642`; state 3 throughout. **But
  the applied configuration did not survive the reboot**:
  `/tmp/system.cfg` was the FACTORY baseline `b1df1da2…` (not the applied
  `6656ecc3…`), authorized_keys was 0 lines (users plugin off the factory
  config), and the record's vap_table held only the factory vap
  (mac-derived essid, ch11) while the `wlan_cfg` bookkeeping still
  reported `confirmed` with the applied WLANs — `in_sync` regressed to
  `false` and the engine kept answering noops on the matching cfg echo,
  never re-provisioning: the settle watchdog is one-shot, not a
  continuous invariant. The device retains the per-device key, the inform
  URL, and the cfgversion stamp across reboots, but NOT the applied config
  — the real controller evidently pairs provisioning with a save/persist
  step this controller does not implement (next bytecode question).
  Recovery demonstrated (user-approved second baseline-clear, 08:14Z):
  self-heal minted `ce4b246b66e513cc` → full provisioning with
  BYTE-IDENTICAL pushed bytes `6656ecc3…` → settle count 2, `in_sync`
  true, both vaps RUN. Bench left settled; operator key re-deployed (it
  does not survive reboots or provisioning applies — see the findings
  above).
- **Matrix outcome this round**: A1 `PROVEN`; A2 `FAILED` (the retention
  criterion — the reboot regression above; the other three A2 criteria are
  evidenced); F1 `PROVEN`; F2 `BLOCKED` on its final client-side
  sub-criterion (no test client at the bench — the same environment
  condition as the C1-shape round; the backup/reset/verify/re-adoption
  sub-steps are all evidenced above). B1/B2/B3/C1/C2/D1/E1 unchanged
  `NOT RUN`; C3 unchanged `BLOCKED`; release claim unchanged.
- **Harness/zz steady state**: `live-applied-sys.txt` re-seeded to the
  device-verified bytes `6656ecc3…`; `live-devices.json` refreshed from the
  store — its `ssh_sha512passwd` cache (`$6$AB12CD34$…`) pairs with the
  baseline's password row (the `TestZZLiveIntentVsApplied` 0/0 contract);
  `live-wireless.json` unchanged (envelope untouched). `make check`:
  green — go vet + all packages; `TestZZLiveIntentVsApplied` reproduces
  the 0/0 steady state with the refreshed record, all night gates pass,
  `TestZZLiveWpaCandidateVsApplied` skips (envelope unchanged).

### 2026-09-18 verify round (fixed adoption baseline + not-running re-arm; controller 97a7e095d1e4a0e8)

Scope: live-prove both engine fixes from `0a21a3f` end-to-end with NO
store surgery — the F-chain re-run (F1 → factory reset → re-adopt →
automatic envelope delivery) and the A2 reboot — then re-seed the
harness caches. Same bench, operator remote, no test client (all
client-side rows unchanged). All times UTC; controller log lines are
+02:00.

- **Pre-round state**: repo main `0a21a3f`; controller redeployed from
  it (`97a7e095d1e4a0e8…`; rollback
  `openunifi.rollback-20260918T111204Z` holds the pre-fix
  `296fb60b…`); approved backups: bench
  `devices.json.bak-20260918T111339Z` +
  `wireless.json.bak-20260918T111339Z`, local
  `tmpwork/harness-20260917/f2-backup-20260918T111339Z/`; envelope
  untouched (id `2dab5684…`). Retained-key steady state on the new
  binary verified before the round: GCM noops ~15 s cadence, cfg echo
  `ce4b246b…`, state 3, `in_sync` true, delivery confirmed, zero mints.
- **F1 re-proven (11:14:39Z)**: `DELETE /api/v1/devices/aabbccddee02`
  → `200 {"mac":"aa:bb:cc:dd:ee:02","status":"deleted"}`; list empty;
  retained-key informs escalate to `unregistered device` + `no key
  produced a valid JSON payload` (`tried:1`, ~5.4 s cadence); pending
  candidate sourced `discovery`, `factory=false`.
- **F2a — factory reset (11:17:27–11:20:16Z)**: `syswrapper.sh
  restore-default` over the password lane (host keys regenerate at
  reset — the expect runner pins `UserKnownHostsFile=/dev/null`, no
  impact); ~2 min 45 s dark; factory state verified 11:20:16Z:
  `/etc/version` `BZ.6.8.2`; authorized_keys 0 lines;
  `/tmp/system.cfg` sha256 `b1df1da2…` (factory baseline byte-exact);
  `mca-cli-op info` → `Status: Unable to resolve
  (http://unifi:8080/inform)`; factory announces `factory=true` at the
  10 s cadence.
- **F2b/A1 — fixed-engine adoption chain (11:21:37–11:23:13Z, fully
  automatic)**: `set-inform` 11:21:37Z; `POST
  /api/v1/pending/aabbccddee02/adopt` 11:21:45Z → `200 {"state":1,
  "actions":["delete"]}`; 11:21:53Z flags `0x0003` → `inform: adoption
  push (default key)` → setparam `gcm:false` (mgmt_cfg only, fresh
  per-device key); 11:21:56Z the re-keyed echo (885 B) hits the fix:
  **`inform: no envelope baseline, forcing provisioning`** mints
  `1b42c9d36a01e64a` — exactly where the pre-fix engine answered a
  `connected noop` and never provisioned; 11:22:08Z echo mismatch →
  `inform: full provisioning` (`ours=1b42c9d3…` vs
  `device=08315776…`), system_cfg diagnostic sha256 `0485dca7…`;
  apply-window delivery retries as designed — two `wireless envelope
  drift, forcing full provisioning` re-pushes (11:22:51Z, 11:22:58Z;
  byte-identical, bounded at count 3), one `noop-pending-wlan`
  (11:23:03Z), then **settle 11:23:13Z**: `connected noop` cfg echo
  `1b42c9d3…`, `in_sync` true, delivery `confirmed`; both vaps RUN
  with the envelope id `2dab5684…` (`openunifi-gate-check`; ath0 ng
  ch6, ath1 na ch157). Byte-exact: on-device `sha256sum
  /tmp/system.cfg` = `0485dca7…` = the pushed diagnostic.
  `mca-cli-op info` → `Status: Connected (http://10.10.10.10:8080/inform)`;
  authorized_keys regenerated empty by the users-section apply
  (password lane unaffected). **No store surgery anywhere.**
- **Steady state (11:23:13–11:28:42Z)**: 28 consecutive
  `connected noop`s, ~12 s cadence, zero mints — the self-heal does
  not re-fire once the baseline is captured by delivery proof.
- **A2 re-run — fix #2 live (11:28:47–11:30:48Z, unattended)**: reboot
  over SSH 11:28:47Z; last inform 11:28:42Z, first re-inform
  11:29:59Z — a 77 s gap; re-inform flags `0x000b` (RETAINED
  per-device key, no factory-key phase, no re-adoption), cfg echo
  UNCHANGED `1b42c9d3…` — but the vap_table proves the factory vap
  running (mac-derived essid `AABBCCDDEE02`; only the 2.4 GHz vap up
  at that instant): **retention fails exactly as the morning round
  diagnosed.** The new watchdog catches it on the first inform:
  `inform: applied WLANs not running, forcing re-provisioning`
  (11:29:59Z) → mint `5d16465c6fb7a64b` → `inform: full provisioning`
  11:30:13Z (`ours=5d16465c…` vs `device=1b42c9d3…`) with a
  **byte-identical push `0485dca7…`** (the record's ssh_sha512 cache
  renders deterministically — no fresh salt across re-provisioning);
  settle 11:30:48Z `connected noop` cfg `5d16465c…`, `in_sync` true,
  delivery `confirmed` (count 4); both vaps RUN the envelope again.
  First re-inform to settled: 49 s, zero operator action.
- **A2 criterion outcome**: retention stays `FAILED` device-side — the
  device boots the factory vap while echoing our cfgversion, so the
  save/persist pairing the real controller evidently performs
  (docs/AP-FIRMWARE-APPLY-PATH.md, the standing bytecode question)
  remains the only true fix. With the fixed engine the failure is a
  bounded automatic recovery: the re-armed watchdog re-provisions
  exactly once per not-running proof. Row A2 keeps the `FAILED`
  status on the retention criterion with the automatic recovery now
  live-proven.
- **Watchdog false-positive check / DFS-guard decision**: the watchdog
  fired exactly once per genuine failure (the reboot); zero mints
  across the 28-noop and 54-noop steady windows (vaps RUN, ch 6/157 —
  non-DFS); sparse heartbeats never re-armed. No two-consecutive-miss
  guard is indicated by live evidence; a DFS channel (radar-driven
  vap downtime) stays untested and would re-open the question — the
  guard remains one counter away in `wlanstate.go`.
- **make check regression found and fixed**: this round's
  first check was red — `TestSetupTracingExportsOTLPHTTP` (landed
  hours earlier in the telemetry feature commit, self-skipping under
  a loopback-denying sandbox, so never truly exercised) proved
  otlptracehttp v1.46 uses a `WithEndpointURL` path as-is: a bare
  `http://host:port` `--otlp-endpoint` exported spans to `/` where no
  collector listens. The fix (pathless scheme-URLs gain the canonical
  `/v1/traces`, explicit paths stay verbatim; both cases test-pinned)
  landed as `512f58c` on the original feature hash `106193b`; both
  were later consolidated into `c07a48b` by an autosquash rebase on
  2026-09-18, so the fix and its tests live there now.
  `make check` green end-to-end after the fix. The bench binary
  predates the telemetry feature and tracing is opt-in (not in the
  bench run flags) — no round impact.
- **Bench log hygiene**: `openunifi.log` lines 16684–16690 are stale
  sh errors from the 2026-09-17 09:33–09:36 deploy attempt (a
  non-Linux binary exec'd by the shell between `open-unifi stopped`
  and the next `starting`); they are not runtime data — parse the log
  with `errors='replace'` and skip non-JSON lines.
- **Harness/zz steady state**: `live-applied-sys.txt` re-seeded to the
  device-verified bytes `0485dca7…` (6515 B, fetched as `busybox
  base64 /tmp/system.cfg` over the password lane — through the expect
  pty the output carries a trailing `\r` per line, so strip it before
  decoding); `live-devices.json` refreshed from the post-A2 store
  (35253 B) — its ssh_sha512 cache pairs with the baseline's
  `users.1.password` row (the `TestZZLiveIntentVsApplied` 0/0
  contract); `live-wireless.json` unchanged (envelope untouched).
  `make check` green; `TestZZLiveIntentVsApplied` and all
  `TestZZMinimalDiff*`/`TestZZSuccessivePush*` gates pass;
  `TestZZLiveWpaCandidateVsApplied` skips (envelope unchanged).
- **Bench end state**: settled (state 3, `in_sync` true, both vaps RUN
  the envelope; 54 consecutive clean noops through 11:41:58Z); operator
  key re-deployed over the password lane after the round (it does not
  survive reboots or provisioning applies) — key-only BatchMode ssh to
  the AP verified; backups and the pre-fix rollback binary remain in
  place.
- **Matrix outcome this round**: A1 `PROVEN` (re-proven under the
  fixed engine — adoption now delivers the envelope automatically);
  A2 `FAILED` on the retention criterion with automatic recovery
  live-proven; F1 `PROVEN` (re-proven); F2 still `BLOCKED` on the
  final client-side sub-criterion only — every controller-side
  sub-criterion is now proven with the fix, without surgery.
  B1/B2/B3/C1/C2/D1/E1 unchanged `NOT RUN`; C3 unchanged `BLOCKED`;
  release claim unchanged.

### 2026-09-19 root-cause resolution — A2 retention failure is a controller renderer bug, fixed

**Method (AP forensics, ssh lane):** fetched `/usr/etc/syswrapper.sh`,
`/etc/inittab`, `/etc/init.d/*`, `/etc/rc.d/*`, the full 33-plugin
`/etc/sysinit/*` set, `/proc/mtd`, `/tmp/system.cfg`,
`/etc/persistent/cfg/mgmt`, and `/var/log/messages` (to
`tmpwork/harness-20260917/ap-persist/`); live-probed the persist mechanism
on the AP — flag-consume timing ≤10 s (touch 1789740294 → gone 1789740304),
`cfgmtd -r` MTD-blob extraction returning the applied text sha
`0485dca7…` == the then-current `/tmp/system.cfg`; read the boot preinit
hook `/lib/preinit/99_21_ubnt_ubntconf`.

**Mechanism (every stage now proven; AP-FIRMWARE-APPLY-PATH.md §6.5):**
`save-config`/`apply-config` only set the flag `/var/run/need_cfg_save`;
mca-monitor consumes it via `syswrapper cfg_save_check` →
`cfgmtd -w -p /etc /tmp/system.cfg` packs the applied cfg text +
`/etc/persistent` into the 3-slot MTD blob — the pack chain works and the
blob held the APPLIED text at the A2 reboot. At boot the preinit hook
restores the blob (`cfgmtd -r -p /etc/ -f /tmp/running.cfg`), then guards
the restored text: `grep 'mgmt.is_default=true'` — a hit replaces it with
the factory template before `sort → /tmp/system.cfg`.

**Root cause:** our system_cfg renderer's factory-echo block emitted
`mgmt.is_default=true` (pre-fix render.go:304, echoing the factory
baseline for the zero-diff property). Every reboot of a provisioned AP
therefore factory-reset the cfg text while the tar part still restored
mgmt — retained-key re-inform carrying our cfgversion + factory
vap_table, exactly the observed A2. The real controller never emits the
row (no mgmt writer in config_String/int; `is_default` appears only in
device-state classes).

**Fix (2026-09-19):** `internal/server/systemcfg/render.go` no longer
emits `mgmt.is_default` in any value (comment cites the boot guard);
`render_test.go` golden updated plus a negative guard asserting the row
never returns; `zz_minimaldiff_scratch_test.go` permits exactly the
`mgmt.is_default` row-key as an intended one-time migration delta vs the
pre-fix applied captures — every other mgmt.* delta stays a violation.
Full `go test ./...` green.

**A2 re-run protocol (pending — live bench):** deploy the fixed
controller → let drift or the watchdog land the corrected push → wait
≥15 s (flag consume + pack) → raw reboot → expect the first re-inform
RETAINED key, UNCHANGED cfgversion, RUNNING vaps, no watchdog
re-provision; post-boot `/tmp/system.cfg` = the applied text ROW-SORTED
(compare row-sets, not sha — the boot `sort` reorders rows). Row A2
flips to `PROVEN` only on that round.

### Per-case capture minimum

For every `PROVEN` or `FAILED` case, attach or hash (without secrets):

1. controller log excerpt covering the action and state transition;
2. AP status/config evidence, such as redacted inform fields or status export;
3. client association and DHCP evidence (client alias, lease/subnet, gateway,
   DNS, timestamps);
4. a bounded traffic test result with source/destination labels and timestamps;
5. packet-capture evidence where applicable, including capture interface,
   direction, 802.1Q VID/PCP, and the capture hash; and
6. the exact redacted command/UI action and reviewer sign-off.

## Release gate summary

| Gate | Result |
| --- | --- |
| All A–F required rows are `PROVEN` on firmware 6.8.2.15592 | `OPEN` |
| Every `PROVEN` row has the exact evidence fields and review sign-off | `OPEN` |
| Any `FAILED`, `BLOCKED`, or `NOT RUN` row has a documented disposition | `OPEN` |
| `C3` bridge-apply disposition is reviewed (currently BLOCKED offline — §Bridge-apply verdict: WLAN-count pushes withheld) | `OPEN` |
| End-user WLAN acceptance claim is authorized | `NO — remains gated until the rows above are reviewed` |
