# open-unifi provider — full example
#
# Prereqs (see README.md in this directory):
#   * provider binary built from ./cmd/tfprovider staged under
#     ~/.terraform.d/plugins/dev.open-unifi/lucavb/open-unifi/0.0.1/<os>_<arch>/
#   * dev_overrides block in ~/.terraformrc
#
# Variables keep the token out of state; Configure() also honors
# OPEN_UNIFI_ADMIN_TOKEN when `token` is unset.

variable "controller_url" {
  type        = string
  description = "Base URL of the open-unifi admin API, e.g. http://192.168.1.2:8443 (plain HTTP: the controller has no TLS yet)"
  default     = "http://192.168.1.2:8443"
}

variable "admin_token" {
  type        = string
  description = "Server --admin-token value. Also settable via OPEN_UNIFI_ADMIN_TOKEN."
  default     = ""
  sensitive   = true
}

terraform {
  required_providers {
    open-unifi = {
      source = "lucavb/open-unifi" # resolved via dev_overrides
    }
  }
}

provider "open-unifi" {
  url   = var.controller_url
  token = var.admin_token
  # insecure_skip_verify only matters for https:// URLs; the controller
  # serves plain HTTP today (no TLS yet), so it stays false.
  insecure_skip_verify = false
}

# --- Adopt an access point by MAC ------------------------------------------
# mac must be LOWERCASE colon-separated; the server normalizes, but keep
# lowercase in HCL so plan/apply diffs stay stable. Computed fields (state,
# ip, firmware, last_seen) fill in once the AP checks in and gets adopted.
resource "open-unifi_access_point" "attic" {
  mac  = "78:8a:20:11:22:33"
  name = "attic-ap"
  # site_id defaults to "default"
}

# --- One secure wlan (wpa-p on a tagged vlan) ------------------------------
resource "open-unifi_wlan" "main" {
  name       = "main"
  ssid       = "ExampleNet"
  security   = "wpa-p"
  passphrase = "correct-horse-battery" # min 8 chars; (sensitive value) in plans
  vlan       = 42
  enabled    = true
}

# --- One open wlan (guest) -------------------------------------------------
resource "open-unifi_wlan" "guest" {
  name     = "guest"
  ssid     = "OpenGuest"
  security = "open"
  vlan     = 1
  enabled  = true
  # NOTE: on the single-radio UAP-AC-Pro-Gen2 skinniest configs, two wlans
  # share one radio; the control plane applies both wlans to the same AP.
}

# --- Data source: everything the controller sees ---------------------------
data "open-unifi_devices" "all" {}

output "devices" {
  description = "All known devices (incl. pending adoption)."
  value       = data.open-unifi_devices.all.devices
}

output "attic_ap_state" {
  description = "Adoption state of the attic AP."
  value       = open-unifi_access_point.attic.state
}

output "main_wlan_vlan" {
  description = "VLAN of the main wlan as applied server-side."
  value       = open-unifi_wlan.main.vlan
}
