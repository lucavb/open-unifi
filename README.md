# open-unifi

A minimal, self-contained UniFi control plane for the UAP-AC-Pro-Gen2 (`U7PG2`):
inform/adoption protocol server, admin REST API + web console, Prometheus
metrics, and a Terraform provider. Wire behavior was reverse-engineered
byte-for-byte from the official controller's bytecode — see `docs/`.

Not a firmware replacement: the AP keeps its stock firmware and is managed
over the standard inform channel.

## Layout

- `cmd/openunifi/` — controller binary (inform server, UDP discovery, admin API, metrics).
- `cmd/tfprovider/` — Terraform provider binary (terraform-plugin-framework, protocol 6).
- `provider/` — provider implementation (client, `access_point`/`wlan` resources, `devices` data source).
- `internal/inform/` — inform packet codec: 40-byte header, AES-128-CBC, AES-GCM (header-bound AAD), zlib.
- `internal/server/` — inform handler, adoption state machine, `mgmt_cfg`/`system_cfg` builders, UDP :10001 discovery listener.
- `internal/store/` — device persistence (JSON-file backed, atomic writes).
- `internal/adminapi/` — REST under `/api/v1/*`, bearer-token auth, embedded web console at `/`.
- `internal/app/` — glue: Backend adapter over the store, wireless config persistence, metrics poller.
- `internal/metrics/` — Prometheus collectors (`openunifi_*`).
- `internal/adminapi/static/index.html` — the embedded web console (go:embed; single source of truth).
- `docs/` — protocol specifications (bytecode-cited).
- `examples/terraform/` — provider usage with local dev overrides.

## Build & run

```
make check          # full module gate: gofmt + vet + test
make build          # go build ./...
make test           # go test ./...
make provider-build # dist/openunifi-tfprovider
```

```
go run ./cmd/openunifi \
  --listen-inform :8080 \
  --listen-admin 127.0.0.1:8443 \
  --listen-discovery :10001 \
  --discovery \
  --data-dir data \
  --controller-url http://<this-host>:8080 \
  --admin-token <secret>
```

All flags: `--listen-inform` (device inform endpoint), `--listen-admin`
(admin API/console/metrics), `--listen-discovery` + `--discovery` (UDP 10001
announce listener), `--data-dir` (devices.json, wireless.json, site-settings.json), `--controller-url`
(the URL devices should inform to; embedded in the pushed config),
`--regulatory-country-code` (ISO 3166-1 numeric code used in generated wireless
configuration; defaults to 840/US and is not a claim of regulatory approval),
`--admin-token`
(bearer auth for `/api/v1/*` AND `/metrics`; empty disables auth entirely and logs
a loud startup warning — env fallback `OPEN_UNIFI_ADMIN_TOKEN`), `--ap-ssh-password`
(env `OPEN_UNIFI_AP_SSH_PASSWORD`; SSH password provisioned onto adopted APs;
empty = site default `ubnt`), `--ap-ssh-key` (repeatable; env
`OPEN_UNIFI_AP_SSH_KEY`; one authorized_keys line per occurrence, provisioned as
`sshd.auth.key.<n>` rows — LAB ONLY, live pushes behind `--allow-gated-live-wlan`),
`--allow-plaintext-inform` (reject by default, like the real controller),
`--log-level`, `--log-format` (logging is human-readable TEXT by default;
`--log-format json` / env `OPEN_UNIFI_LOG_FORMAT=json` opts into one-JSON-object-per-line
output — this flips the prior always-JSON behavior),
`--otlp-endpoint` (opt-in OTLP/HTTP tracing, e.g. `http://127.0.0.1:4318`; empty = tracing
off unless `OTEL_EXPORTER_OTLP_ENDPOINT(_TRACES)` is set; `http://` = plaintext transport,
`https://` = TLS; `OTEL_SDK_DISABLED=true` force-disables; standard
`OTEL_EXPORTER_OTLP_HEADERS/TIMEOUT/COMPRESSION`, `OTEL_SERVICE_NAME`,
`OTEL_RESOURCE_ATTRIBUTES` are honored natively by the SDK). When tracing is on, JSON
log lines carry `trace_id`/`span_id` (see `docs/alloy-openunifi.example.alloy` for a
Grafana Alloy example wiring OTLP into Tempo and the controller log into Loki). A corrupt
`wireless.json` refuses startup rather than silently provisioning the AP with zero WLANs.

The AP-intent settings above (`--regulatory-country-code`,
`--ap-ssh-password`, `--ap-ssh-key`) are
first-boot seeds: they initialize `<data-dir>/site-settings.json` only when
that file does not exist yet. After that the persisted record is the single
source of truth — manage it through `PUT /api/v1/site-settings` or Terraform
(`open-unifi_site_settings`, below); a save that changes the record mints
`cfgversion` and every adopted AP picks the new sshd rows up at its next
inform. Caveat on default-gated deployments (U7PG2 firmware 6.8.2.15592):
a save that carries provisioned SSH public keys still returns 200 — but
every subsequent full provisioning, including
the delivery of future WLAN changes, is rejected with the typed 501
live-provisioning gate until the sshd facts are cleared (an effective
site-settings save of the defaults) or the controller restarts with
`--allow-gated-live-wlan` (startup-only; a runtime save can never lift the
gate). The rejected inform aborts its whole store cycle, so record
absorption freezes too — affected devices go stale in the console (they
look dead, not gated). See `docs/PROTOCOL-systemcfg-wireless.md` §13.
Supplying any of the three when the record already exists logs a
startup warning and the record wins (the deployment-input flags like
`--controller-url` are unaffected).

## Onboarding a factory AP

1. Start the controller on a host the AP can reach.
2. On the AP (SSH, factory creds): `set-inform http://<controller-host>:8080/inform`.
3. The AP's first inform appears in the console's *Adopt candidates* (or
   `POST /api/v1/pending/<mac>/adopt`).
4. The controller pushes `mgmt_cfg` with a fresh per-device `x_authkey`;
   the AP re-keys automatically and reports back. Full provisioning
   (`cfgversion` + `system_cfg` + `blocked_sta` + `mgmt_cfg`) follows,
   carrying the WLAN/VLAN configuration.
5. Heartbeats settle into `noop` responses with a 15 s interval; state,
   uptime, client counts, and traffic appear on `:8443/metrics`. An adopted
   device silent for more than ~3 minutes is marked `lost` (state 4) and
   recovers on its next inform.

## Admin API (JSON, bearer when `--admin-token` set)

```
GET/POST      /api/v1/devices          list / register (adopt whitelist)
GET/PATCH/DELETE /api/v1/devices/{mac}
GET/POST      /api/v1/devices/{mac}/blocked     list / block a client
                                          (POST body {"mac":"<client>"}; idempotent)
DELETE        /api/v1/devices/{mac}/blocked/{client}   unblock (404 when not blocked)
POST          /api/v1/devices/{mac}/reboot          arm remote reboot
                                          (fires on the device's next inform)
POST          /api/v1/devices/{mac}/factory-reset   arm remote factory reset
                                          (fires on the device's next inform)
GET           /api/v1/pending           unadopted devices heard so far
POST          /api/v1/pending/{mac}/adopt
GET/PUT       /api/v1/wireless          whole-doc WLAN config ({"wlans":[…]})
GET/PUT       /api/v1/site-settings     the AP-intent site facts (whole-doc PUT)
GET           /api/v1/devices/{mac}/radios          per-radio echo + admin intent
PUT/DELETE    /api/v1/devices/{mac}/radios/{radio} set / clear per-radio intent
GET           /api/v1/whoami
GET           /metrics                  Prometheus (requires the token when one is set)
GET           /healthz
```

Device PATCH fields (strict body, unknown fields rejected): `name`
(1–64 chars, no control characters; `""` clears), `site_id`
(1–64 chars, `A–Z a–z 0–9 . _ -`, leading alphanumeric), and
`led_override` (`"on"` | `"off"` | `"default"`, where `"default"` clears
the override back to the site default). Omitted fields are left unchanged.
The response is the updated device view.

Blocking a client takes effect on the device's next inform: the controller
delivers the blocked list inside the same `setparam` that carries
`system_cfg` (the `blocked_sta` field), exactly like a WLAN change — a
fresh `cfgversion` is minted and the AP confirms it by echoing the new
version back.

Wireless fields per WLAN: `name`, `ssid`, `security` (`open` | `wpa-p` |
`wpa-eap`), `passphrase` (≥8, required for `wpa-p`, rejected for `open`,
optional for `wpa-eap`), `vlan` (1–4094),
`enabled`. `wpa-eap` requires an inline RADIUS profile:
`radius_servers` (1–4 `{ip, port}` auth servers, port default 1812),
`radius_secret` (shared secret, emitted verbatim), and
`radius_vlan_mode` (`disabled`/`optional`/`required` → system_cfg
`dynamic_vlan` 0/1/2). Radius fields on non-EAP WLANs are rejected.
Control characters are rejected in all
fields (they would inject `system_cfg` rows). Disabling a WLAN removes it
from the pushed config entirely.

Per-radio intent: `PUT /api/v1/devices/{mac}/radios/{radio}` with
`{"channel": 36}` and/or `{"txpower": 8 | "auto"}` (wholesale replace —
absent fields clear). Intent survives inform echoes, rides full
provisioning after a one-per-change cfgversion bump, and overlays the
device's radio_table echo in the rendered `radio.<n>.channel`/`txpower`
rows. Validation: channel `ng` 0–14 / `na` 0 or 36–165; fixed txpower
must fit the device-reported bounds; unknown bands are rejected.

## Terraform

```hcl
terraform {
  required_providers {
    open-unifi = { source = "registry.terraform.io/lucavb/open-unifi" }
  }
}

provider "open-unifi" {
  url   = "http://10.0.0.5:8443"
  token = var.admin_token
}

resource "open-unifi_access_point" "ap" {
  mac  = "f0:9f:c2:84:8f:2a"
  name = "office-ap"
}

resource "open-unifi_wlan" "corp" {
  name       = "corp"
  ssid       = "corp"
  security   = "wpa-p"
  passphrase = "correcthorsebatterystaple"
  vlan       = 42
}

resource "open-unifi_site_settings" "site" {
  regulatory_country_code = 840
  ap_ssh_password         = "s3cret-ap-passphrase"
  ap_ssh_public_keys      = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… admin@workstation"]
}
```

`open-unifi_site_settings` is a singleton (one record per controller,
id `site-settings`) managing the AP-intent site facts — the
regulatory country code, the AP SSH password, and the provisioned
authorized_keys lines (ordered; one `sshd.auth.key.<n>` row family per
line). A change to any of them
re-provisions every adopted AP at its next inform. Deleting the resource
restores the controller defaults. Watch the live gate before combining
these fields: the example above (provisioned `ap_ssh_public_keys`) is
exactly the sshd provisioning the gate
blocks on the supported hardware (U7PG2 firmware 6.8.2.15592) — the apply
succeeds, but every subsequent full provisioning returns the typed 501
until the sshd facts are cleared (an effective save of the defaults) or
the controller restarts with `--allow-gated-live-wlan` (startup-only),
and blocked devices then go stale in the console; see
`docs/PROTOCOL-systemcfg-wireless.md` §13.

See `examples/terraform/` (includes filesystem-mirror dev overrides so
`terraform init` isn't needed during development).

## WLAN provisioning status

Live WLAN provisioning is unsupported/gated pending an official-controller
differential fixture. On U7PG2 firmware 6.8.2.15592 the gate fails closed
with a typed status and never emits `system_cfg`, on EITHER trigger: any
nonempty managed WLAN, OR site-fact sshd provisioning (provisioned SSH
public keys). The startup-only
`--allow-gated-live-wlan` flag lifts it for sanctioned bench pushes.

## Protocol documentation

- `docs/PROTOCOL.md` — inform wire format, crypto, JSON shapes, adoption FSM.
- `docs/PROTOCOL-mgmt.md` — response envelope, `mgmt_cfg`/`system_cfg`/`blocked_sta` builders, full response catalog.
- `docs/PROTOCOL-discovery.md` — UDP/10001 packet + TLV tables.
- `docs/PROTOCOL-systemcfg-wireless.md` — `radio.*`/`aaa.*`/`wireless.*` schema, VLAN/bridge wiring, `users.1` password format.

Note on provenance: the protocol docs occasionally cite `decomp/…` source names
from the untracked local decompilation workspace (source jar
`tmpwork/data/usr/lib/unifi/lib/ace.jar`, canonical `javap` dumps
`tmpwork/javap/**`); neither the decomp/ outputs nor the decompiled jar are
committed — they are derivative works of Ubiquiti's controller and deliberately
stay out of the tree.

## Threat model

Operational security: the admin listener defaults to `127.0.0.1:8443` and
requires a nonempty bearer token. For remote administration, place it behind
an HTTPS reverse proxy; native admin TLS is intentionally not provided, and
non-loopback plaintext requires the explicit lab-only `--allow-insecure-admin`.
`--allow-anonymous-admin` and `--allow-default-ap-ssh-password` are likewise
explicit lab-only exceptions. Use the proxy's HTTPS URL for controller and
Terraform provider access.

The inform protocol has no device certificates: pre-adoption identity is the
public factory key (`MD5("ubnt")`) plus a MAC claim, and by protocol design
any holder of a device's current or previous key can read that device's
re-key pushes (rotation responses are sealed with the key the device just
used). open-unifi keeps the classic semantics and adds: unencrypted informs
are rejected unless `--allow-plaintext-inform` (and the plaintext path never
rotates keys or initiates adoption), a two-key rotation window (stale keys
stop decrypting after one re-key hop), device inform bodies can never inject
`system_cfg` rows, and per-MAC read-modify-write serialization in the store.
**Run the inform and admin ports on a trusted L2 segment** — the admin port
is plain HTTP with bearer auth only.

`data/devices.json` holds live per-device keys (chmod 0600, gitignored);
`data/wireless.json` holds WLAN passphrases. Treat both as credentials.
The data directory has an exclusive advisory lock to prevent concurrent JSON
writes. Keep it private, encrypt backups, and restore the complete directory
only while stopped. Terraform state can contain tokens and WLAN passphrases;
store it in an encrypted, access-controlled backend with versioned backup and
restore.

## Status & limitations

Byte-exactness, scoped: parts of open-unifi are **verified byte-exact against
the official Linux controller's bytecode** — the crypto layer (AES-128-CBC
including the lenient-padding fallback, AES-GCM with header-bound AAD,
sha512crypt-vs-commons-codec password format), the response envelope, and the
discovery framing. A jar-anchored differential test harness does not exist yet
(see Limitations), so "byte-exact" claims are scoped this way rather than
end-to-end verified.

Known deviations from the classic controller, **fixed in the current fix
wave** (documents updated accordingly): the `radio.<n>.ieee_mode` resolver
(`docs/PROTOCOL-systemcfg-wireless.md` §3.1), `wpa` default 3 (jar AUTO=3), the
per-vap `radio.<n>`/`radio.<n>.virtual.<d>` companion rows, `dhcpc.<n>`
status+devname rows, the `noop.interval` JSON-number type (open-unifi sends a
fixed 15), `inform_url` gating, invented `# sshd`/`# misc` config headers, and
the device-lost window.

Still open (classic behavior vs open-unifi):
- snappy inform payloads (flag `0x04`): the **classic controller decompresses
  them** (`org.xerial.snappy`, `docs/PROTOCOL.md` §1); open-unifi rejects them.
  Live note (2026-09-16): 6.8.2 never sets the bit — flags stayed `0x0003`
  (zlib, CBC) pre-adoption and `0x000b` (zlib + AES-GCM) after, so the
  rejection path never fired.
- discovery replies (cmd-8 announce replies and the "invoke sshd" cmd-10 push):
  classic replies when discoverable (`docs/PROTOCOL.md` §4); open-unifi is
  announce-only. Live note (2026-09-16): replies are not required for adoption
  — the U7PG2 adopted via set-inform with zero server-side UDP/10001 traffic.
- WPA-EAP/RADIUS (2026-09-19): supported via the admin API + web console
  with an inline RADIUS profile per WLAN (auth servers, shared secret,
  dynamic-VLAN mode); accounting (radius.acct), DAS/DAD, interim-update,
  keyid and filter_id rows are omitted (docs/PROTOCOL-systemcfg-wireless.md
  §12). The Terraform provider still pins security to open|wpa-p — radius
  fields there are a follow-up. Live EAP association against a bench
  RADIUS server is not yet proven (see acceptance docs).
- No firmware upgrade / `upgrade` responses; no hotspot2/WPA3/SAE emission.
- `system.analytics.status` is not emitted (see Limitations).
- Real-device **protocol/control-plane evidence** was captured on 2026-09-16
  (UAP-AC-Pro-Gen2 / U7PG2, firmware 6.8.2.15592): adoption, default-key
  push + key rotation, provisioning, WLAN config push, and steady-state noops
  were live-verified; see `docs/PROTOCOL.md` §7. This is not an end-user WLAN
  acceptance claim: client association, DHCP, traffic forwarding, tagged VLAN
  observation, WLAN mutation/deletion, multi-radio coverage, loss/recovery,
  and factory-reset/re-adoption remain release-gated. Use the repeatable
  evidence matrix in `docs/WLAN-ACCEPTANCE-6.8.2.15592.md`; do not describe
  unrun rows as passed.
- Admin port is plain HTTP (token auth) — TLS is a TODO; run on a trusted LAN.

### Limitations

- **No jar-anchored differential test harness.** Byte-exactness claims are
  grounded in bytecode citation, not yet in an automated golden-comparison
  against captures from a real classic controller (FID-57).
- **Single-process store (FID-63).** The data directory is guarded by an
  exclusive advisory lock taken at startup; a second controller process
  against the same `--data-dir` fails fast ("data directory … is already
  in use") instead of racing JSON writes.
- **Plaintext inform mode (`--allow-plaintext-inform`).** The response to a
  re-key push echoes the device's *current* authkey as cleartext on the wire.
  Opt-in flag for a reason; trusted lab segments only (FID-42).
- **`system.analytics.status` is not emitted.** The classic controller emits
  this system_cfg row only when the device reports analytics-toggle support
  (`Device.supportAnalyticsToggle()` — model capability + minimum firmware
  version gate, tmpwork/javap/com__ubnt__data__Device.txt:7552-7576). Not yet in
  the open-unifi builder (FID-72).
