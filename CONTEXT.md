# open-unifi

A self-contained UniFi control plane for the UAP-AC-Pro-Gen2 (`U7PG2`): an
inform/adoption protocol server, admin REST API + web console, Prometheus
metrics, and a Terraform provider. Wire behavior is reverse-engineered
byte-for-byte from the official controller's bytecode.

## Language

### Protocol

**Inform**: the encrypted HTTP POST a device sends the controller to report
state and fetch its next instruction. One of the inform `_type`s is a
heartbeat; not every inform is.
_Avoid_: heartbeat (that names one inform type), poll.

**Adoption**: the handshake that moves a pending candidate to an adopted
device — a `mgmt_cfg` push carrying a fresh per-device key, applied by the
device on its next inform.
_Avoid_: onboarding, enrollment.

**Pending candidate**: an unadopted device the controller has heard (via
inform or discovery) but not adopted.
_Avoid_: unknown device, orphan.

**Key rotation**: replacing a device's per-device key (`x_authkey`) during
adoption. The factory default key never survives adoption.
_Avoid_: re-key, rekeying.

**Factory default key**: the pre-adoption shared key every factory device
uses (MD5 of "ubnt").
_Avoid_: default authkey.

**cfgversion**: the version stamp of the config a device runs. An inform
whose cfgversion matches gets a noop; a mismatch gets full provisioning.

**Drift**: the state where the config a device reports running no longer
matches the config the controller intends.

**Full provisioning**: the `setparam` response that carries cfgversion,
system_cfg, blocked_sta, and mgmt_cfg together.
_Avoid_: config push (ambiguous — adoption also pushes config).

**Noop interval**: the seconds-to-next-inform the controller returns when
nothing is pending. Chosen by the jar-cited scheduling formula, not a
constant.
_Avoid_: poll interval.

**Discovery**: the UDP :10001 announce protocol devices broadcast and the
controller listens to.

### Wireless provisioning

**WLAN**: a managed wireless network config (name, SSID, security,
passphrase, VLAN, enabled).
_Avoid_: vap (that is the per-radio instance emitted into system_cfg),
network.

**Wireless envelope**: the whole-document WLAN config (`{"wlans": [...]}`),
replaced wholesale on change.
_Avoid_: wireless config (too vague).

**Drift settle**: the confirmation flow that watches a pushed WLAN until the
device's vap_table proves it running, keeping the last-known-good WLANs
intact while waiting.
_Avoid_: WLAN sync.

**Delivery retry**: the bounded attempt bookkeeping for a WLAN push the
device has not yet confirmed.
_Avoid_: retransmit (nothing is resent at the transport level).

### Trust policy

**Controller-owned keys**: record fields the controller preserves verbatim
against device overwrite (the wlan_cfg_* bookkeeping, the ssh_sha512
password cache).
_Avoid_: protected fields.

**Device-refreshable caps**: record fields only the device can supply
(radio_table, wifi_caps, fw_caps, if_table, ethernet_table, uplink) —
preserved across sparse heartbeats, refreshable by a full inform.
_Avoid_: device attributes.

**Admin-owned rows**: record fields only an admin can set or change
(system_cfg_extra_lines, mgmt_dev, anonymous ids). A device can neither
write nor introduce them.

### Decision modules (the inform path)

**Adoption engine**: the single decider for every decoded inform — adoption,
drift settle, delivery retry, full provisioning, or noop — given the device
state. Transport and crypto sit outside it.
_Avoid_: inform handler (that is the transport adapter), state machine,
dispatcher.

**Inform codec**: the module that turns an inform body into a decoded
inform and an outcome into response bytes — framing, crypto, and
compression live behind it. The JSON payload (noop, setparam, reboot,
setdefault) is assembled by the transport adapter; the codec seals
already-built bytes.
_Avoid_: crypto layer (that names a byte-exactness scope, not the module),
packet parser.

**system_cfg renderer**: the pure producer of config text from a device,
the WLANs, and site facts. It reads nothing else and mutates nothing.
_Avoid_: builder, emitter.

**Site facts**: the controller-level inputs a render needs: controller URL,
regulatory country code, AP SSH password, and the current WLANs.

## Commits

Scope commits by the package they change: `adminapi` (the REST surface),
`app` (the Backend), `adoption` (engine decisions), `server` (transport),
`acceptance` (live-round records) — so `git log --grep` works. Feature-word
scopes (`admin`, `wireless`, `led`, `radio`) are drift; do not add new ones.
