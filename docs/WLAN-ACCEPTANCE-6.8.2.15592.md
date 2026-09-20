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
| A1 | **Factory adoption:** factory AP is discovered/adopted; AP reports adopted/connected; controller records the expected model and firmware; post-adoption inform is received. | `PROVEN` | §2026-09-18 F-row live round — adoption chain 07:32:47–07:34:09Z (adoption-seed engine finding recorded there); §2026-09-18 verify round — re-proven under the fixed engine, adoption delivers the envelope automatically 11:21:45–11:23:13Z; §2026-09-20 factory-window set-inform round — the console path re-proven with ZERO operator SSH keystrokes: Forget → Accept → controller-pushed set-inform 12:13:56.881 → first inform 12:13:56.886 on the factory default key → full provisioning 12:14:11.951 → settle state 3 / `in_sync`, AP bytes byte-identical to the push (`ad41cdad…`) |
| A2 | **Restart with retained key:** adopted AP is restarted without deleting controller state; it re-informs using the retained key, returns to connected, and receives/retains the expected configuration. | `PROVEN` | §2026-09-18 F-row live round — 74 s gap + retained-key re-inform + cfg echo unchanged proven 08:09–08:12Z; applied config did NOT survive the reboot (recovery via the tested self-heal remedy); §2026-09-18 verify round — retention failure re-confirmed and automatic watchdog recovery live-proven 11:29:59–11:30:48Z; §2026-09-19 root cause resolved — the renderer's `mgmt.is_default=true` factory-echo row tripped the AP preinit boot guard (`/lib/preinit/99_21_ubnt_ubntconf` replaces the MTD-restored text containing it with the factory template; docs/AP-FIRMWARE-APPLY-PATH.md §6.5); fix in render.go; §2026-09-19 A2 re-run — retention PROVEN live: retained-key first re-inform (+67 s) with unchanged cfgversion echo, post-boot `/tmp/system.cfg` byte-identical to the push (`3da7ce3e…`), vaps RUN, 6.5 h steady state; one benign not-running-watchdog boot-race re-provision recorded (two-consecutive-miss guard now live-indicated — see the 2026-09-19 round record); §2026-09-19 full-chain round — controller-armed §6.5 reboot: `kind=reboot` on the retained key, echo unchanged, NO boot-race miss (device came up RUN); post-boot `/tmp/system.cfg` is the fw-sorted re-emission, row set byte-identical to the push |
| B1 | **WPA-Personal association:** WPA-Personal test client associates to the intended SSID on 2.4 GHz and 5 GHz as applicable; client receives DHCP lease and can pass the defined allowed traffic test. | `NOT RUN` | `________________` |
| B2 | **Open association:** open test client associates; client receives DHCP lease and can pass the defined allowed traffic test. | `NOT RUN` | `________________` |
| B3 | **Tagged VLAN:** WPA-Personal and/or open test WLAN configured with a tagged VLAN; client associates and receives DHCP on the intended subnet; traffic passes; capture on the AP uplink visibly records 802.1Q with the expected VID (or records the exact reason the observation point cannot see the tag). | `NOT RUN` | `________________` |
| C1 | **SSID/passphrase/VLAN update:** change the SSID, passphrase, and VLAN; old credentials/SSID no longer work as expected, new credentials associate, DHCP is from the new VLAN, traffic passes, and AP/controller state reflects the update. | `NOT RUN` | `________________` |
| C2 | **WLAN deletion / VAP disappearance:** delete or disable a WLAN; controller config omits it, AP `vap_table`/equivalent no longer shows the VAP on each applicable radio, and the client can no longer associate to it. | `NOT RUN` | `________________` |
| C3 | **Bridge-apply survival (WLAN-count change):** change the WLAN count so the rendered bridge port list changes (e.g. remove the 5 GHz vap); the AP stays reachable through the apply (inform continues), br0 recovers its address and uplink, and remaining WLAN service recovers. If the AP darks, capture the failure with console access ready — the offline verdict predicts exactly that. | `NOT RUN` | offline: §Bridge-apply verdict; tmpwork/harness-20260917/night-deltas.txt |
| D1 | **Multiple WLANs on both radios:** configure at least two WLANs, with intended 2.4 GHz and 5 GHz coverage; each expected VAP is present, clients associate to each, receive the correct DHCP/VLAN result, and pass the defined traffic test. | `NOT RUN` | `________________` |
| E1 | **AP lost/recovery:** isolate or power off the AP; controller marks it lost within the documented window; restore connectivity/power; AP re-informs, returns connected, and WLAN client service recovers. | `NOT RUN` | `________________` |
| F1 | **Controller-side deletion:** delete the adopted AP/controller device record using the approved procedure; record resulting AP state and confirm the expected re-adoption path without claiming success unless completed. | `PROVEN` | §2026-09-18 F-row live round — deletion 07:25:55Z; decrypt-failure informs at escalated cadence; pending sourced from discovery announces; re-adoption completed under F2; §2026-09-18 verify round — re-proven under the fixed engine 11:14:39Z |
| F2 | **Factory reset, deletion, and re-adoption:** after approved backup, factory-reset the AP, verify it returns to factory state, remove/clean its old controller record as required, adopt it again, and repeat the minimum WLAN association/DHCP check. | `BLOCKED` | §2026-09-18 F-row live round — backup/reset/factory verify/re-adopt all proven 07:27–07:34Z; final association/DHCP check NOT RUN: no test client at the bench (same environment condition as the C1-shape round); §2026-09-18 verify round — full chain re-proven automatically under the fixed engine 11:17–11:23Z (mint → provisioning → byte-exact settle, no store surgery); client-side sub-criterion unchanged; §2026-09-19 full-chain round — armed `setdefault` on the retained key; demotion swept the per-device key and the whole `wlan_cfg_*` family; factory recovery via `set-inform`; inform-time adoption push from the demoted pending record (no admin adopt call); settle on the FIRST provisioning attempt; boot-guard (`mgmt.is_default=false`), fresh rotated key, and byte-exact `3da7ce3e…` re-proven on the factory-recovered device; client-side sub-criterion still not run; §2026-09-20 factory-window set-inform round — factory reset → console Forget → console Accept → controller-pushed set-inform chain re-proven, click-to-adopted ≈100 s, key rotation + ssh_sha512 re-mint (fresh crypt salt) recorded, AP byte proof `ad41cdad…`; client-side sub-criterion still not run |

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
  - **Radio-lane channel-intent candidate** (2026-09-19; zz harness
    record + `Extra["radio_intent"]={"wifi1":{"channel":36}}`, gate-check
    both-band open): new successive-push gate
    `TestZZSuccessivePushChannelIntentVsApplied` requires exactly one
    intended row — `radio.2.channel: "0" -> "36"` (radio 2 = wifi1 na) —
    and zero unmanaged violations. Gate compiles and skips in worktrees
    (baseline absent); **first run on the postmortem workstation main
    checkout post-merge, recording the gate listing + candidate sha256
    here, is a live-proof obligation before any production
    channel-intent push.** The {radio} restart set is NOT yet
    live-evidenced (every live round restarted {wireless, aaa} only) —
    see the radio-lane obligations below.
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

**A2 re-run protocol (executed 2026-09-19 00:29–00:33 CEST; AP-side
verified ~07:07 CEST) — A2 flips to `PROVEN`:**

- Fixed controller deployed (`./deploy-bench.sh`, binary `217a608644ae`);
  AP settled at cfg `5d16465c6fb7a64b`, flags `0x000b`. Verbatim envelope
  PUT: correctly no drift. Passphrase-change PUT (`…20260918` →
  `…20260919`) → drift 00:29:12 → setparam carrying the FIXED render
  (system_cfg diagnostic sha256 `3da7ce3e13bcd67b5035eb18f6ff63288fac431
  6d5d3af0aa410f5d64c9b2df6a`; key list jumps `mgmt.flavor` →
  `dhcpd.status` — no `mgmt.is_default` on the wire). Settle 00:29:59
  (new mint `bf4daa59…`, ~47 s).
- AP-side pre-reboot (key lane): `/tmp/system.cfg` `mgmt.is_default`
  row count **0**, sha == `3da7ce3e…` byte-exact (the renderer emits
  sorted rows, so the boot `sort` later proves a no-op); blob probe
  (`cfgmtd -r`) extracted text == applied text (`3da7ce3e…`) — the MTD
  blob held the corrected text before the reboot.
- Raw reboot 00:31:00 (BusyBox `reboot` over the uid-0 `ubnt` lane).
  Boot confirmed by uptime arithmetic (23839 s at ~07:07 → boot
  ~00:31), fresh `mcad` PID 1391, and exactly one post-boot discovery
  announce 00:32:06.648. First re-inform 00:32:07 (+67 s): flags
  `0x000b` — **retained key**; cfg echo `bf4daa59…` — **the applied
  cfgversion, not factory**. Retention proven.
- **Watchdog boot-race finding (new, recorded for follow-up):** that
  first inform's vap_table was present, non-empty, and showed the
  applied SSID not yet RUN (radios still in boot bring-up), so
  `appliedNotRunning()` fired per its documented contract → fresh mint
  `59d7b3e1` → byte-identical re-push 00:32:11 → settle 00:32:29 (18 s),
  steady connected noops since. The re-provision was benign and
  unattended, but the false-fire means the not-running watchdog needs a
  boot-grace (the two-consecutive-miss counter in `wlanstate.go`,
  previously "not indicated by live evidence", is now live-indicated).
- Post-boot + 6.5 h AP-side verification (password lane — the
  users-apply wipes `/etc/dropbear/authorized_keys`, the file this
  dropbear build reads; `/etc/persistent` copies don't survive, the
  blob skips dot-dirs — operator key re-deployed per bench practice):
  `/tmp/system.cfg` sha `3da7ce3e…` (row-for-row the pushed bytes),
  `mgmt.is_default` count 0, blob == applied, ath0 (11ng) + ath1 (11ac)
  both Master broadcasting `openunifi-gate-check`.
- Gates re-seeded to the round's device-verified state:
  `live-applied-sys.txt` (3da7ce3e…), `live-devices.json`,
  `live-wireless.json` from the running controller;
  `render-fixed-sys.txt` regenerated post-fix (sha256 `48dbb631…`,
  synthetic night reference); `TestZZLiveWpaCandidateVsApplied` skip
  updated (both wpa-p rounds complete). All ZZ gates green; full
  `go test ./...` green (11 packages).
- **Verdict: A2 `PROVEN`** — retained key, retained cfg echo, returned
  to connected, expected configuration retained across a raw reboot.
  The boot-race watchdog false-fire is an engine follow-up, not a
  retention failure.

### 2026-09-19 radio lane — per-radio admin intent (offline implementation)

Per-radio channel/txpower intent (admin-owned `Extra["radio_intent"]`,
admin API `GET/PUT/DELETE /api/v1/devices/{mac}/radios[/{radio}]`,
renderer overlay on `radio.<n>.channel`/`txpower`) is implemented,
renderer- and trust-policy-tested offline. Originally recorded with no
live radio-intent push; **live-evidenced 2026-09-19 in the full-chain
round below**: the gated channel-36 candidate applied byte-exact on the
AP and the `{radio}` restart set survived live; obligations 1–2 closed,
obligation 3 partially (echo-matches-intent observed live; the
adversarial old-echo render precedence remains offline-covered).
**Live-proof obligations before the first production
channel-intent push:**
1. Run `TestZZSuccessivePushChannelIntentVsApplied` on the postmortem
   workstation main checkout (tmpwork/harness-20260917 present) and
   record the gate listing + candidate sha256 here.
2. Live-evidence the `{radio}` restart set: push the gated
   channel-intent candidate with `--allow-gated-live-wlan`, verify
   apply (`/tmp/system.cfg` sha match) and that the intended
   `radio.2.channel=36` row survived the device's apply path.
3. Live-verify intent-vs-echo precedence: after apply, a full inform
   carrying the old channel in its radio_table must NOT revert the
   rendered row (admin intent wins in the next full provisioning render).
4. txpower_mode is RESOLVED as a pure echo (2026-09-19 txpower lane,
   PROTOCOL-systemcfg-wireless.md §9: the config classes carry no
   controller-side writer — echo reads int.txt 5687-5696 with default
   "auto", row emission int.txt 5942-5958, pool-ref sweep; echo-pinned
   by internal/server/systemcfg/render_txpower_test.go) — admin
   semantics stay forbidden: no bench observation may mint them without
   a further jar citation first. Country-specific channel legality
   (DFS): the gate machinery is recovered as evidence only (§9 —
   country row via `R.forfloat()` default 840, `channels_na_dfs`,
   `has_dfs`/`has_fccdfs` capability words, the guarded dfs-reset cron
   row), but the gate's caller and the cron-guard producer stay
   untranscribed, so channel legality remains the device's apply-time
   oracle; those two links close only from a full int.txt/String.txt
   session.

### 2026-09-19 full-chain round — EAP push, delivery-storm fix, §6.5 reboot, §6.6 factory reset (controller `1e4c14f4a226` → `95bfc84fe3b2b6a5`)

**Scope:** the full approved destructive chain on bench AP-1
(`aabbccddee02`, U7PG2, 6.8.2.15592), 07:16–08:40 UTC (09:16–10:40
CEST): deploy + regression, LED off/default, blocked_sta block/unblock,
radio-intent channel 36/clear (closing the radio-lane obligations
above), wpa-eap push + revert (which live-found and fixed a
delivery-retry defect), §6.5 armed reboot, §6.6 armed factory reset +
re-adoption. Pre-round backups: remote
`data/devices.json.bak-20260919T071637Z` +
`data/wireless.json.bak-20260919T071637Z`; local preround copies
(devices sha256 `688b28b6…`, wireless `5620a15d…`).

**Deploy + regression:** binary `1e4c14f4a226` (rollback
`openunifi.rollback-20260919T071704Z`); post-swap retained-key GCM
noops with cfg echo `59d7b3e1…` steady — the swap invisible to the
device.

**LED (off/default):** mint `75af095d…` → full provisioning carrying
the byte-identical baseline system_cfg (`3da7ce3e…`); AP-side
`/etc/persistent/cfg/mgmt` gained `mgmt.led_enabled=false` with
`mgmt.cfgversion=75af095d…` and `mgmt.is_default=false`; default
revert mint `ed8e3890…`, `mgmt.led_enabled=true`. Both settled.

**blocked_sta (§4 writer, §6.2(d) delivery):** block POST → inform-time
content drift (no admin-time mint) → setparam → mint `61b46516…` →
settle; the device persisted the wire string verbatim
(`/etc/persistent/cfg/blocked_sta`, 17 bytes, the test MAC). Idempotent
re-block: no drift. Unblock DELETE → drift → mint `9e461fa3…` →
settle; DELETE of an absent MAC → 404. **FW quirk recorded:** fw 6.8.2
does NOT clear `/etc/persistent/cfg/blocked_sta` when pushed the empty
set — the stale MAC stays in the file after unblock; the
controller-side set remains the source of truth (the classic
controller's empty push hits the same firmware behavior).

**Radio intent:** PUT wifi1 channel 36 → mint `6284f648…` → AP
`/tmp/system.cfg` == gated candidate sha256
`278882152b6f0ea8…becfea` byte-exact (`radio.2.channel=36`, ath1 Master
at 5.18 GHz — the `{radio}` restart set survived live); DELETE → mint
`3d5487c3…` → baseline restored (`3da7ce3e…`, `radio.2.channel=0`, ath1
auto-picked ch157). Obligation 3 is evidenced live only in the
echo-matches-intent direction (post-apply radio_table echoed 36; no
revert churn between push and delete); the adversarial old-echo render
precedence remains offline-covered.

**wpa-eap push — delivery storm found (controller `1e4c14f4a226`):**
the gated EAP envelope (inline RADIUS `10.10.10.10:1812`, test-only
secret, `dynamic_vlan=0`) applied byte-exact — AP `/tmp/system.cfg` ==
candidate `15e48396…`, `aaa.1/2.wpa.key.1.mgmt=WPA-EAP`, radius rows,
`wireless.1.authmode=1` unchanged — but the delivery never settled: the
device emitted ONLY sparse informs (741–745 B, no `vap_table`; 60+ in
3.5 min, zero full) at its ~5 s post-apply quick cadence, and the
engine re-minted the cfgversion on every drifted inform, which kept the
pending gate's operatorMint escape permanently true: re-provisioning
every ~5 s, `wlan_cfg_attempts` 37 with `WlanMaxAttempts` never
engaging, the device echo chasing fresh mints (`in_sync` unreachable).
Root cause: `engine.go`'s envelope-drift mint fired per INFORM for a
still-PENDING envelope instead of once per content change; the
exhausted-retry unit tests only ever modeled seeded sha==envelope
states (unreachable via the real settle flow), so the storm was
live-only.

**Fix + live re-validation (controller `95bfc84fe3b2b6a5`):** the mint
is now conditional on the drifted envelope differing from the pending
sha — one mint per delivery operation; re-offers carry the stable
version, `WlanRetryDue`'s bounded budget governs them, and an echoed
offer reaches the equality branch's `noop-pending-wlan` instead of
minting the equality away. Regression
`TestEnvelopeDriftDeliveryIsBounded` models the exact live storm
(settled record + admin envelope change + sparse-only informs) and
asserts ≤ `WlanMaxAttempts` offers, one stable cfgversion across all
offers, the exhausted cap holding, echo-catch noops, full-inform
settle, and a fresh-envelope fresh mint. Re-push of the SAME EAP
envelope live: 4 offers total, one cfgversion (`e7b1f8ee…`) on every
offer, echo caught ≤ 10 s, `noop-pending-wlan` during backoff, settle
**confirmed in 53 s** end-to-end; AP bytes `15e48396…` byte-exact.
Revert to the wpa-p baseline: 2 offers, settle 32 s, AP bytes back to
`3da7ce3e…`.

**§6.5 armed reboot:** POST `/reboot` armed `pending_command: reboot`;
the next inform answered `kind=reboot` (gcm, retained key); ~2:07 dark;
post-boot retained-key noops with echo `d7e0342b…` unchanged, no mint,
no not-running miss (the device came up RUN — the two-miss watchdog
stayed idle), status confirmed. **Finding:** post-boot
`/tmp/system.cfg` is the firmware's alphabetically sorted re-emission
(sha `28ea7f9f…`); its row set is byte-identical to the pushed
document (`3da7ce3e…`) — byte gates apply to pushed document order;
post-boot AP-side evidence is the sorted re-emission.

**§6.6 armed factory reset + re-adoption:** POST `/factory-reset` →
`kind=setdefault` on the retained key → record demoted (state 1,
cfg/applied cleared, per-device key swept, the whole `wlan_cfg_*`
family wiped) → AP dark ~6 min in factory state. Recovery over the
default-password SSH lane: `mca-cli-op set-inform` → factory inform
(flags `0x0003`, reply gcm=false) → engine adoption push from the
demoted pending record (prevState=1; inform-time — no admin adopt call
needed) → re-keyed echo +3 s (gcm=true) → no-baseline self-heal mint →
full provisioning (ours `8977bcd2…` vs adoption echo `980ddd95…`) →
**settle on the first attempt** → steady connected noops. AP-side:
`mgmt.is_default=false` (boot-guard fix holding on a factory-recovered
device), fresh rotated per-device key (≠ pre-reset), `mgmt.cfgversion`
== controller's, `mgmt.use_aes_gcm=true`, `/tmp/system.cfg` byte-exact
`3da7ce3e…`, blocked_sta re-pushed empty (file absent).

**Gates:** fixtures re-seeded from the post-round controller (devices:
state 3, cfg `8977bcd2…`, rotated key; wireless: the wpa-p baseline);
`live-applied-sys.txt` re-verified `3da7ce3e…` against the AP; all ZZ
gates green (BlockedSta/RadioIntent/EAP/Intent PASS, Wpa SKIP by
design); `go vet` + full `go test ./...` green including the new
regression.

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

### 2026-09-19 gap-closure round 1 — five offline citation lanes (controller `77fa34f` → `f4a2af5`)

**Scope:** offline implementation round only — no bench traffic, no
live evidence claimed. Five lanes ran as isolated Orca worktree
workers (run `run_c869df330cd9`), each citation-first (jar javap
transcription packets or protocol-doc sections in code comments; unsettleable
values shipped as BLOCKED verdicts), each with a green scoped
verification trio in its worktree, merged in order sessions → tasks →
acct → ledbar → txpower (rebase + ff-only; conflicts resolved at the
adoption-engine key list, the console, the app view, and the §12
deviation table — all additive unions). Post-merge main: gofmt/vet
clean, full `go test ./...` green including all ZZ live gates.

| lane | commits | outcome |
|---|---|---|
| sessions | `38860b9`…`37372f3` (8) | client session tracking end-to-end: per-client station-table decode (inform), session rows + connect/disconnect events (store), the §6.2(e) blocked_sta reconnect push fired on a client disconnect while blocked (adoption engine, one-shot, no cfgversion mint), connect/disconnect counters (metrics), session refresh in the inform RMW cycle (server), `GET /api/v1/devices/{mac}/clients` + console listing (adminapi) |
| tasks | `31838f8`,`eed4122`,`e93c304` (3) | §6.3 cmd task passthrough: stored admin-owned `cmd_task` row (at most one armed), engine branch after setdefault/reboot (armed task outranks drift), byte-exact `_type:"cmd"` replay over the inform codec, `POST /api/v1/devices/{mac}/cmd`; six §6.3-silent choices recorded as BLOCKED |
| acct | `064bd9a` (1) | §12 rows 1013-1014: `aaa.<n>.radius.acct.<i>.*` rows emitted per accounting server (port 0→1813, profile secret, auth-mirrored slot semantics), `interim_update.*` at the jar's 3600 default; das/dad BLOCKED (client-IP source unrecovered), row 1015 stays omitted (Uid gate unreachable for U7PG2) |
| ledbar | `e28e329`,`6c6b3c6`,`f3334d3` (3) | §12 row 1007 block emitted row-for-row per the javap packet (supportLedBar guard, status/persistent/brightness/active/color rows, `(255*b)/100` truncation, `Color.decode` fallback); knobs `led_override_color_brightness`/`led_override_color` wired adminapi→app→renderer + console; §12 row 1007 flipped implemented |
| txpower | `c1451a3`,`f4a2af5` (2) | §9 txpower_mode RESOLVED as a pure echo (end-2 BLOCKED verdict: no controller-side writer exists — packet pool-ref sweep); echo-pinning tests; DFS gate machinery + guarded dfs-reset cron recorded as evidence-only with two open links |

**ZZ permit:** the ledbar block renders for every capture-predating
baseline, so `f79c826` adds the self-inerting `zzExemptLedBarMigration`
filter (the `zzExemptIsDefaultMigration` precedent) at the stale-baseline
gates; it becomes inert at the next device-verified applied-bytes
re-capture, after which a `ledbar.*` drift trips the gates again.

**Live-proof obligations (the parent's bench queue; none are
live-evidenced yet):** sessions — pin the `sta_table`/`mac` wire key,
the (e) trigger mapping and byte shape, empty-table semantics, session
retention, console/API smoke (WORKER-REPORT-sessions.md §LIVE-PROOF);
tasks — classic-controller enqueue capture (row `type` value, second
enqueue, task fate across reboot/factory reset, accepted cmd bounds);
acct — jar-recover the dad/das client-IP source first, then the live
accounting push/Interim-Update session proof, accounting-off revert,
console round-trip; ledbar — the block's bytes in a captured full
provisioning and real LED state changes per override; txpower — the
echo rows on the next captured provisioning and the §3.2 txpower arm
live-proven (observation may not mint admin semantics — obligation 4
above). Full lane reports: scratch
`/tmp/3fe1d3752fe0b1c6/opencode/fleet-20260919/reports/`.

**Post-round flip (same day):** the acct lane's jar-recovery obligation
is closed offline from the main-checkout javap dump
(tmpwork/javap/com__ubnt__service__config__int.txt): the DAS/DAD client
rows' `<ip>` is the acct server beans' own admin-configured field
(X.getString(srv,"ip",""), int offsets 564-736), gated on
`accounting_enabled` && `radius_das_enabled` && the device fw_caps
0x100000 bit (hasCapability(1048576), int 1500-1539). The knob is now
accepted behind a requires-accounting gate, the rows are emitted
byte-exact (the dad block dad.status/dad.port=3799 once per device
render, das.status + das.port=3800+n + dad.status per emitted index —
the jar's duplicate dad.status preserved — and das.client/das.secret
once per index, dad.client.<i>.cidr=`<ip>`/32 per server),
WlanListHash joins the knob under the accounting gate (the
envelope-external capability arm recorded as a bounded residual), and
§12 row 1014 / §4.3 / §8 are flipped implemented. The bench AP's
fw_caps (0xE7FD3F3F) carries the bit. The live half is closed by the
2026-09-20 round below: the accounting push with das on and the
accounting-off revert are device-verified byte-exact; the
Interim-Update session proof and console round-trip remain open.

### 2026-09-20 DAS/DAD live round — gate-open push, byte-exact AP proof, accounting-off revert (controller `f3a0d41` → binary `3c117b06c5a2`)

**Scope:** live verification of the post-round flip (the das/dad
emission + `radius_das_enabled` acceptance) on bench AP-1
(`aabbccddee02`, U7PG2, 6.8.2.15592), 08:31–08:41 CEST: deploy +
regression, the full-accounting push, AP byte proof, accounting-off
revert, harness re-seed + a standing live gate. Pre-round backups:
remote `data/devices.json.bak-20260920T063134Z` (sha256 `cf30ca67…`) +
`data/wireless.json.bak-20260920T063134Z` (`5620a15d…`).

**Deploy + regression:** binary sha256
`3c117b06c5a26270…77141dd5969` (rollback
`openunifi.rollback-20260920T063158Z`); post-swap retained-key GCM
noops with cfg echo `8977bcd245bd7b44` steady — the swap invisible to
the device.

**Full-accounting push (gate open):** PUT `gate-check` re-secured to
wpa-eap with auth `10.10.10.10:1812`, acct `10.10.10.10:1813`,
interim_update on, `radius_das_enabled` on (test-only secret;
passphrase preserved — under EAP the psk row keeps the real value,
the jar's `letmeinnow` default is only for an empty passphrase).
HTTP 200 echo with `radius_das_enabled:true` — the acceptance
live-proven (the pre-flip binary rejected the same PUT). Drift
08:34:52 → mint `15d681812508bc41`, 3 offers (one cfgversion on all),
echo caught in 15 s (`noop-pending-wlan`), steady connected noops by
08:36:29 — `in_sync:true`, `wlan_delivery_status:confirmed`, restart
set `{aaa}` (no other section moved).

**AP byte proof** (default-key SSH lane, commands redacted):
`/tmp/system.cfg` sha256 `f60d458ee1c0…d3f3a79` == the pushed
document; `mgmt.cfgversion=15d681812508bc41` == the mint. Rows
exactly per the javap packet: `aaa.1.radius.dad.status=enabled` +
`dad.port=3799` once per device render (aaa.1 only),
`das.status=enabled` + `das.port=3801`/`3802` per emitted index, the
jar's duplicate `dad.status` preserved (twice under aaa.1, once under
aaa.2), `das.client`/`das.secret` once per index,
`dad.client.1.cidr=10.10.10.10/32` + `.secret` per server slot, acct
rows port 1813, auth rows port 1812, `interim_update.status=enabled` +
`.interval=3600`. The ledbar block rides both this and the reverted
capture — the first captured full provisioning with the §12 row 1007
block — and the `radio.*` `txpower_mode=auto`/`txpower=auto` echo rows
are in both captures (obligation-4 observation evidence, no admin
semantics minted). Client assoc/traffic/capture evidence is N/A: the
bench runs no RADIUS daemon; the round validates envelope shape, the
`{aaa}` restart set, and the das/dad byte shape on the wire.

**Accounting-off revert:** PUT the wpa-p baseline back → mint
`f9ea3a736d628506`, 3 offers, echo caught in 13 s, steady noops ~24 s
end-to-end; AP bytes `c4b7f3bf6f8e…641503c` with das/dad/acct/interim
row count 0 (the gate closes silently), `wpa.psk` restored, ledbar
retained; controller `wireless.json` sha `5620a15d…` identical to the
pre-round backup — the envelope restored byte-for-byte.

**Gates + harness re-seed:** `live-applied-sys.txt` re-seeded from
the reverted AP bytes (`c4b7f3bf…`; the prior capture preserved as
`live-applied-sys.preround-20260920.txt`); `live-devices.json`
`082fd789…`; `live-wireless.json` `5620a15d…`; the das-state capture
archived as `live-das-applied-sys.txt` (`f60d458e…`).
`zzExemptLedBarMigration` is retired at the live gates (the
`zzExemptIsDefaultMigration` precedent — the re-seeded capture is
post-ledbar, so a `ledbar.*` drift trips them again); the filter
stays only at the synthetic-baseline gates. New standing gate
`TestZZLiveDasCandidateVsApplied` (secret = the pushed constant): the
render reproduces the device-verified das-state bytes byte-exact —
render sha256 == capture sha256 `f60d458e…`, parse-level zero-diff,
the duplicate dad.status asserted in raw counts (2× aaa.1, 1× aaa.2)
— and vs the applied baseline: 37 intended deltas, all inside
`aaa.*`, zero violations, zero `wireless.*` rows. All ZZ gates green
(11 PASS + Wpa SKIP by design); `go vet` + full `go test ./...` green.

**Obligations:** closes the flip's live half — accounting push with
das on, accounting-off revert (both device-verified byte-exact).
Gap-closure evidence banked: the ledbar block's bytes in a captured
full provisioning (real-LED-state half remains) and the txpower echo
rows in a captured provisioning (§3.2 arm remains). Still open:
Interim-Update session proof (needs a live RADIUS acct daemon),
console round-trip, sessions `sta_table` pin, tasks
classic-controller capture.

### 2026-09-20 live gap-closure round 2 — the no-RADIUS obligations: tasks cmd, console round-trip, radio §3.2 arm, ledbar, sessions, destructive tail (no deploy — binary `3c117b06c5a2…` unchanged)

**Scope:** live evidence for every gap-closure obligation that needs
no RADIUS daemon, on bench AP-1 (`aabbccddee02`, U7PG2, 6.8.2.15592),
08:57–11:16 CEST, same binary as the morning DAS/DAD round (no
deploy). Pre-round backups `data/devices.json.bak-20260920T0657Z`
(`a7dfb41c…`) + `data/wireless.json.bak-20260920T0657Z`
(`5620a15d…`); the wireless envelope stayed `5620a15d…` the whole
round.

**Tasks §6.3 cmd lane:** three enqueues (spectrum-scan,
clear-all-dpi-counters, spectrum-scan) all 200 with
`pending_command:"cmd"`; exactly ONE fire — 08:57:55 `armed cmd task
cmd=spectrum-scan` → `kind=cmd` gcm=true — the second enqueue
REPLACED the first (no earlier cmd ever fired), and the fire minted
NOTHING (connected noops with cfg echo `f9ea3a736d628506`
unchanged). Accepted bounds live-proven: `""` → 400 `cmd is
required`, 65 runes → 400 `cmd must be at most 64 characters`,
edge-whitespace → 400 `cmd must not begin or end with whitespace`
(`ValidateCmdString` — deliberately no whitelist). Stored row shape
`{cmd, mac}` only; the classic-controller row `type` value remains a
capture obligation.

**Console round-trip (acct):** the console HTML carries the full
accounting surface (5× `accounting_enabled`, 6× `acct_servers`, 5×
`interim_update_enabled` bindings); envelope GET (199 bytes) → PUT
back byte-verbatim → 200 `wireless config replaced wlans=1`, no
mint; `wireless.json` sha `5620a15d…` unchanged and the envelope
re-GET byte-identical — the round-trip is lossless.

**§3.2 radio intent arm (txpower):** PUT `{"txpower":18}` → mint
`083860ed2cef6d56`, drift settle ~17 s; AP rows `radio.2.txpower=18`
with `txpower_mode=auto` UNMINTED (observation mints no admin
semantics — the §9 verdict, now live), sha `ee745fdd…`. Adversarial
stale-echo: PUT `{"channel":36,"txpower":18}` 09:02:34.116 with the
window capture 09:02:34.122 showing intent `channel:"36"` against
`echo_channel:"0"` → settle `af955d9810e3f006`, AP rows
`radio.2.channel=36`, sha `48c6482b…` — the renderer keys on the
intent layer, not the stale echo (live precedence proof). Restore
`{"channel":0,"txpower":"auto"}` → `c09f85e474c5c584`; DELETE the
intent layer → one more mint cycle (wholesale-replace doctrine, even
though render-from-echo is byte-identical) → settle
`b43ec476e200ee1a`; AP back to the `c4b7f3bf6f8e…641503c` baseline,
radios view pure echo. Observation: the radio_table echo rows did
NOT flip while the 36/18 rows ran (echo stayed `0`/`auto`) — the
echo is not per-push channel telemetry; drift settle keys on
cfgversion.

**Ledbar overrides (§12 row 1007):** PATCH red@50 % → settle
`98dcd2817a0068bf` (09:07:41); AP rows `status=enabled`,
`persistent=true`, `brightness=127` ((255·50)/100 truncated),
`active=3`, `color.1.color=3`, `r=255 g=0 b=0`, sha `9c0a96d5…`.
PATCH `off` → settle `f2bf17a982205040` (09:08:51); AP rows
`status=disabled` + `persistent=true` only (ROWCOUNT 2), sha
`a3adb25d…`. Revert (`default`/100/`""`) → view omits every LED
knob, settle `6ed64ead42dd467c`, AP rows back to the enabled/255/blue
baseline, sha `c4b7f3bf…` — the byte path closed end-to-end;
lamp-level eyes-on deferred (Tuesday).

**Sessions empty-table:** `GET /api/v1/devices/{mac}/clients` →
`{"clients":[]}` stable through every full inform of the round, no
decode errors — empty-table semantics live. The client-dependent
halves (wire key, the §6.2(e) trigger, retention) still need a real
client.

**Destructive tail — task fate across reboot, then across factory
reset:** ENQ `clear-all-dpi-counters` + POST `/reboot` → `armed
reboot` 09:58:09 → `kind=reboot` → device marked lost 09:59:28 →
first return inform 10:00:12.901 (announce `factory=false`, uptime
39): `armed cmd task cmd=clear-all-dpi-counters` → `kind=cmd`
gcm=true on the RETAINED per-device key — the task SURVIVES the
reboot branch; connected noops on `6ed64ead42dd467c` (cfg echo
retained across the raw reboot — persistence, no re-provisioning);
`cmd_task` row count 0 after the fire. Then ENQ `spectrum-scan` +
POST `/factory-reset` 10:07:45 → `armed setdefault (factory reset)`
10:07:58 → `kind=setdefault`, record demoted (state 1) — the task is
DISCARDED at the decision (the setdefault branch outranks and
deletes): zero `armed cmd task` lines ever after, `cmd_task` refs 0
in the record. The AP factory-reset (~10:08:31 boot), announcing
`factory=true` every ~10 s with ZERO informs 10:08–10:23 — without
an inform URL the device cannot reach the controller, and the
discovery announce carries none (the §3 verdict, live). The demoted
record did NOT appear in `GET /api/v1/pending` (`{"pending":[]}`) —
a factory-reset known device flows through record demotion +
inform-time adoption, not the pending-candidate lane.

**Recovery (approved default-password SSH lane):** the reset wiped
authorized_keys, so the §6.6 lane ran from the workstation:
`mca-cli-op set-inform http://10.10.10.10:8080/inform` (ubnt/ubnt) →
factory inform 10:23:02.474 (flags `0x0003`) → **adoption push from
the demoted pending record** (`prevState=1`, factory-default-key
sealed, gcm=false — no admin adopt call) → re-keyed inform
10:23:04.986 (flags `0x000b`, gcm=true) → no-baseline self-heal mint
→ full inform 10:23:20.271: render diagnostic sha `c4b7f3bf…` —
byte-identical to the pre-round applied baseline — full
provisioning (ours `7def53c29e16e7a3` vs device echo
`9038e8d23ee7987e`, gcm=true) → **settle on the first attempt**
(connected noops on `7def53c29e16e7a3` by 10:23:55) → poller 1→2→3.
Key rotation complete (fresh per-device key ≠ pre-reset).
Persistence re-proof on the recovered device: POST `/reboot`
11:13:25 → return inform 11:15:33 on the RETAINED fresh key, cfg
echo `7def53c29e16e7a3` intact (boot-race grace: `applied WLANs not
running, miss 1 of 2` on the sparse first inform, both up on the
next), no re-provisioning — state 3 by 11:15:43.

**AP-side proof (post-round, over the restored operator key lane):**
`/etc/persistent/cfg/mgmt` reads `mgmt.is_default=false` (the
boot-guard holding on a factory-recovered device),
`mgmt.cfgversion=7def53c29e16e7a3` == the mint, and
`mgmt.use_aes_gcm=true` (the rotated key on the GCM lane). The
post-reboot on-disk `/tmp/system.cfg` is the firmware's sorted
re-emission (raw sha `3560a780…`) whose row set is byte-identical to
the pushed document — sorted sha `27aa4247…` on both sides, 268
rows, zero diff — the A2-resolution post-boot semantics (byte gates
apply to pushed document order).

**Side findings:** (1) the default-password SSH lane is automation-hostile this
round: six expect-driven attempts (25/45/90 s timeouts, pre- and
post-reboot, immediate and 1 s-delayed sends, with and without a
pinned auth order) all hung at the password prompt — no reject, no
session, no eof — while the operator's interactive `ssh-copy-id` on
the same lane completed minutes later and re-installed the operator
key (authorized_keys had been regenerated empty by the users-apply;
1 line again), restoring the key lane. Root cause unexplained: the
§6.6 automation worked against the factory sshd state, the hangs are
all against the applied config, and interactive works against both.
Recovery procedure note: drive the set-inform/key-install lane
interactively when the key lane is down. Direct AP-side reads
re-opened over the key lane and are complete (the AP-side proof
above). (2) poller state dips to 2
exactly inside drift windows (mid-settle 09:07:28 / 09:08:43 /
09:57:13 and the 10:23:13 post-re-key snapshot), returning to 3 at
settle, with informs connected noops throughout — the dip is the
drift state, not a link loss. (3) the discovery reply remains a
documented TODO (PROTOCOL.md §4 — listen-only today); the factory
window is live-consistent with the §3 verdict: a reply would only
make the device visible — the inform URL still rides the SSH
set-inform channel.

**Gates + harness re-seed:** `live-devices.json` re-seeded from the
post-round record (state 3, cfg `7def53c29e16e7a3`, rotated key;
fixture sha `a20042ac…`), prior fixture archived as
`live-devices.preround-20260920-round2.json` (`082fd789…`);
`live-wireless.json` unchanged (`5620a15d…`); `live-applied-sys.txt`
unchanged (`c4b7f3bf…` — equal to the recovery render diagnostic, so
no re-capture) and re-verified against the AP post-round (sorted
row-set sha `27aa4247…` both sides). All ZZ gates green on the churned record (11 PASS +
Wpa SKIP by design — the churned record renders the applied bytes
byte-exact at `TestZZLiveIntentVsApplied`); `go vet` clean; gofmt
clean on repo code; full `go test ./...` green.

**Obligations:** closed this round — console round-trip (lossless,
no mint); tasks cmd lane (one-fire replay, second-enqueue replaces,
bounds, no whitelist); task fate across reboot (retained) and across
factory reset (discarded at the setdefault decision); §3.2 txpower
arm, `txpower_mode` never minted, adversarial stale-echo precedence,
DELETE clears; the ledbar override byte path; sessions empty-table
+ API listing; factory recovery with settle on the first attempt,
key rotation, and persistence re-proven on the recovered device.
Still open: Interim-Update session proof (live RADIUS acct daemon),
client-dependent session halves (wire key, §6.2(e) trigger,
retention, association), the classic-controller cmd row `type`
capture, ledbar lamp eyes-on, the SSH password lane's
automation-hostility (expect hangs, interactive works — root cause
unexplained), and the discovery reply emitter (documented TODO,
unscheduled).

### 2026-09-20 factory-window set-inform round — controller-pushed set-inform: zero-SSH-keystroke console adoption (lane commits `037d367` → `3cfde29`, binary `f09dbb852f7d`)

**Scope:** live verification of the controller-side SSH set-inform
push lane: a factory window driven entirely from the console — the
operator clicks Accept on a pending candidate and the controller
pushes the inform URL over SSH itself; no operator SSH keystroke
anywhere in the chain. Bench AP-1 (`aabbccddee02`, U7PG2, 6.8.2.15592),
12:07–12:16 CEST. Lane: `037d367` (single-source the inform URL the
controller hands devices) + `3cfde29` (the push lane —
internal/app/setinform.go, armed by `--allow-ssh-set-inform-push`,
one-shot push fired between the pending-candidate commit and the
adopt API return, 502 mapping on push failure). Pre-round backups:
local `live-devices.preround-20260920T100620Z.json` (`a20042ac…`),
bench `data/devices.preround-20260920T100622Z.json` (`3f943682…`),
local `live-applied-sys.preround-20260920T124833Zround3.txt`
(`c4b7f3bf…`).

**Deploy + arm:** binary sha256 `f09dbb852f7d` (rollback
`openunifi.rollback-20260920T100709Z`); the bench start line carries
`--allow-ssh-set-inform-push`; lane armed with
`inform_url=http://10.10.10.10:8080/inform`.

**Factory window:** POST
`/api/v1/devices/aa:bb:cc:dd:ee:02/factory-reset` (colon-MAC) armed
10:07:57Z → `kind=setdefault` delivered 12:07:58 local; record
demoted to state 1, armed tasks discarded (the round-2 verdict).
Factory announces every ~10 s from 12:09:11 (`factory=true`), zero
informs — the §3 verdict live again: without an inform URL a factory
device cannot reach the controller, and the discovery announce carries
none.

**Console path — two UX findings:** the demoted state-1 record still
bore the MAC, so `GET /api/v1/pending` returned `{"pending":[]}` —
ListPending skips record-bearing MACs, now observed twice. The
operator clicked **Forget** in the console, the next announce promoted
the MAC to a pending candidate (~10 s), then **Accept**. Through the
window every console poll threw `devices: tbody is not defined` —
the clients-expansion refactor had orphaned the LED-bar save wiring
inside `updateOpenClients`, out of `tbody`'s scope, so the LED Save
buttons were dead on the bench console. Fixed in `4208e8b` (the block
re-homes into `renderDevices`); rides the next deploy.

**The push + adoption chain (the round's proof):** Accept 12:13:55.856
→ **`set-inform: pushed` 12:13:56.881**
(`mac=aa:bb:cc:dd:ee:02 ip=10.10.10.20 outcome=pushed
url=http://10.10.10.10:8080/inform`); the adopt API call returned 200 in
1033 ms. First inform 12:13:56.886 — 5 ms behind the push log line,
`prevState=1`, sealed on the factory default key, gcm=false: an
inform-time adoption push with no admin adopt call and no operator
keystroke → adoption setparam; full provisioning 12:14:11.951
(system_cfg sha256 `ad41cdad…`, cfg_version `46733c22476f0d95`).
Settled by ~12:15:36: state 3, `in_sync:true`, cfg echo == mint,
`wlan_delivery_status:confirmed` (count 1) — click-to-adopted ≈100 s.
Key rotation complete: the post-round record carries a fresh
per-device key — the factory default key did not survive the adoption.

**AP byte proof (operator key lane, commands redacted):** the
setdefault wiped authorized_keys (the users-apply regenerates it
empty — round-2 behavior), so the operator's ssh-copy-id reinstalled
the key, this time from the workstation. `/tmp/system.cfg` captured
from the workstation: 6659 bytes, sha256
`ad41cdad4bd63e54…dec22c21ac9` == the pushed full-provisioning
render — byte-identical. Side-finding: the applied system_cfg carries
NO cfgversion row — the stamp rides the setparam envelope only; the
device's reported cfgversion (== the mint `46733c22476f0d95`) proves
application. The controller-owned ssh_sha512 cache re-minted with a
fresh crypt salt — same underlying site default password
(`ssh_password_configured=false` at startup; no `--ap-ssh-password`
configured).

**Gates + harness re-seed:** `live-devices.json` re-seeded from the
post-round record (state 3, cfg `46733c22476f0d95`, rotated key;
fixture sha `5d1548dc…`); `live-wireless.json` unchanged
(`5620a15d…`); `live-applied-sys.txt` re-seeded from the round's own
AP capture (`ad41cdad…`). Post-round, all three live gates had
tripped on exactly one row — `users.1.password`, the re-adoption
re-mint — against the stale baselines; the re-capture clears
intent/eap/das-vs-applied, and `9a2baa7` adds `zzExemptSSHReMint`
(the `zzExemptIsDefaultMigration` pattern), carried only at the das
gate's archive comparison (`live-das-applied-sys.txt` `f60d458e…`
predates the re-adoption; only a next DAS push round re-seeds it —
its one filtered row is exactly the re-mint). Final, on the merged
tree (`1d6b56a` record-absorption, that lane's in-flight follow-up
work present): the full ZZ family green — intent steady state
byte-identical (0 intended, 0 violations), eap candidate 14 intended
all inside `aaa.*`, das candidate 37 intended all inside `aaa.*` and
parse-identical to the das archive modulo the exempted row,
blocked_sta byte-identical, radio intent one row `radio.2.channel
0→36`, Wpa SKIP by design; full `go test ./internal/...` green.

**Obligations:** closes the zero-SSH-keystroke adoption path — the
console Accept now carries a factory device to adoption on its own;
the §6.6 interactive recovery lane remains the fallback when the key
lane is down. Recorded for the next deploy: the tbody fix (`4208e8b`)
restores the LED Save wiring on the bench console; the pending-list
skip (a demoted record needs a console Forget first) is a
twice-observed UX candidate, no code change this round. Still open
(carried): Interim-Update session proof, the client-dependent session
halves, the classic-controller cmd row `type` capture, ledbar lamp
eyes-on, the SSH password lane's automation-hostility, the discovery
reply emitter.

## Release gate summary

| Gate | Result |
| --- | --- |
| All A–F required rows are `PROVEN` on firmware 6.8.2.15592 | `OPEN` |
| Every `PROVEN` row has the exact evidence fields and review sign-off | `OPEN` |
| Any `FAILED`, `BLOCKED`, or `NOT RUN` row has a documented disposition | `OPEN` |
| `C3` bridge-apply disposition is reviewed (currently BLOCKED offline — §Bridge-apply verdict: WLAN-count pushes withheld) | `OPEN` |
| End-user WLAN acceptance claim is authorized | `NO — remains gated until the rows above are reviewed` |
