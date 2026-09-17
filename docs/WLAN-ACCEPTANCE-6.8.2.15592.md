# Live WLAN acceptance evidence template

This remains a pending evidence template, not an acceptance claim. Live WLAN
provisioning is gated pending an official-controller differential fixture.

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
| A1 | **Factory adoption:** factory AP is discovered/adopted; AP reports adopted/connected; controller records the expected model and firmware; post-adoption inform is received. | `NOT RUN` | `________________` |
| A2 | **Restart with retained key:** adopted AP is restarted without deleting controller state; it re-informs using the retained key, returns to connected, and receives/retains the expected configuration. | `NOT RUN` | `________________` |
| B1 | **WPA-Personal association:** WPA-Personal test client associates to the intended SSID on 2.4 GHz and 5 GHz as applicable; client receives DHCP lease and can pass the defined allowed traffic test. | `NOT RUN` | `________________` |
| B2 | **Open association:** open test client associates; client receives DHCP lease and can pass the defined allowed traffic test. | `NOT RUN` | `________________` |
| B3 | **Tagged VLAN:** WPA-Personal and/or open test WLAN configured with a tagged VLAN; client associates and receives DHCP on the intended subnet; traffic passes; capture on the AP uplink visibly records 802.1Q with the expected VID (or records the exact reason the observation point cannot see the tag). | `NOT RUN` | `________________` |
| C1 | **SSID/passphrase/VLAN update:** change the SSID, passphrase, and VLAN; old credentials/SSID no longer work as expected, new credentials associate, DHCP is from the new VLAN, traffic passes, and AP/controller state reflects the update. | `NOT RUN` | `________________` |
| C2 | **WLAN deletion / VAP disappearance:** delete or disable a WLAN; controller config omits it, AP `vap_table`/equivalent no longer shows the VAP on each applicable radio, and the client can no longer associate to it. | `NOT RUN` | `________________` |
| D1 | **Multiple WLANs on both radios:** configure at least two WLANs, with intended 2.4 GHz and 5 GHz coverage; each expected VAP is present, clients associate to each, receive the correct DHCP/VLAN result, and pass the defined traffic test. | `NOT RUN` | `________________` |
| E1 | **AP lost/recovery:** isolate or power off the AP; controller marks it lost within the documented window; restore connectivity/power; AP re-informs, returns connected, and WLAN client service recovers. | `NOT RUN` | `________________` |
| F1 | **Controller-side deletion:** delete the adopted AP/controller device record using the approved procedure; record resulting AP state and confirm the expected re-adoption path without claiming success unless completed. | `NOT RUN` | `________________` |
| F2 | **Factory reset, deletion, and re-adoption:** after approved backup, factory-reset the AP, verify it returns to factory state, remove/clean its old controller record as required, adopt it again, and repeat the minimum WLAN association/DHCP check. | `NOT RUN` | `________________` |

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
| End-user WLAN acceptance claim is authorized | `NO — remains gated until the rows above are reviewed` |
