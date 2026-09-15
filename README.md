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
  --listen-admin :8443 \
  --listen-discovery :10001 \
  --discovery \
  --data-dir data \
  --controller-url http://<this-host>:8080 \
  --admin-token <secret>
```

All flags: `--listen-inform` (device inform endpoint), `--listen-admin`
(admin API/console/metrics), `--listen-discovery` + `--discovery` (UDP 10001
announce listener), `--data-dir` (devices.json + wireless.json), `--controller-url`
(the URL devices should inform to; embedded in the pushed config), `--admin-token`
(bearer auth for `/api/v1/*` AND `/metrics`; empty disables auth entirely and logs
a loud startup warning — env fallback `OPEN_UNIFI_ADMIN_TOKEN`), `--ap-ssh-password`
(SSH password provisioned onto adopted APs; empty = site default `ubnt`),
`--allow-plaintext-inform` (reject by default, like the real controller),
`--log-level`. A corrupt `wireless.json` refuses startup rather than silently
provisioning the AP with zero WLANs.

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
GET/DELETE    /api/v1/devices/{mac}
GET           /api/v1/pending           unadopted devices heard so far
POST          /api/v1/pending/{mac}/adopt
GET/PUT       /api/v1/wireless          whole-doc WLAN config ({"wlans":[…]})
GET           /api/v1/whoami
GET           /metrics                  Prometheus (requires the token when one is set)
GET           /healthz
```

Wireless fields per WLAN: `name`, `ssid`, `security` (`open` | `wpa-p` |
`wpa-eap`), `passphrase` (≥8, required for `wpa-p`/`wpa-eap`, rejected for
`open`), `vlan` (1–4094), `enabled`. Control characters are rejected in all
fields (they would inject `system_cfg` rows). Disabling a WLAN removes it
from the pushed config entirely.

## Terraform

```hcl
terraform {
  required_providers {
    open-unifi = { source = "registry.terraform.io/lucabecker/open-unifi" }
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
```

See `examples/terraform/` (includes filesystem-mirror dev overrides so
`terraform init` isn't needed during development).

## Protocol documentation

- `docs/PROTOCOL.md` — inform wire format, crypto, JSON shapes, adoption FSM.
- `docs/PROTOCOL-mgmt.md` — response envelope, `mgmt_cfg`/`system_cfg`/`blocked_sta` builders, full response catalog.
- `docs/PROTOCOL-discovery.md` — UDP/10001 packet + TLV tables.
- `docs/PROTOCOL-systemcfg-wireless.md` — `radio.*`/`aaa.*`/`wireless.*` schema, VLAN/bridge wiring, `users.1` password format.

## Threat model

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

## Status & limitations

- Byte-exact against the official Linux controller's bytecode for the
  implemented surface (magic `TNBU`, factory key, CBC/GCM envelopes,
  adoption handshake, config builders). Six-lens adversarial review with a
  validator round complete; real-device acceptance test: pending — open
  verify-items are tracked in `docs/PROTOCOL.md` §7.
- `wpa-eap` is emitted structurally; RADIUS server fields are not yet part
  of the API surface.
- Admin port is plain HTTP (token auth) — TLS is a TODO; run on a trusted LAN.
- No firmware upgrade / `upgrade` responses, no hotspot2/WPA3/SAE, no
  discovery replies from the controller (announce-only), snappy inform
  payloads rejected.
