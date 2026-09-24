# Terraform provider repository split

Provider binaries and registry releases moved to
[github.com/lucavb/terraform-provider-open-unifi](https://github.com/lucavb/terraform-provider-open-unifi).

- **Registry address** (unchanged): `registry.terraform.io/lucavb/open-unifi`
- **GitHub release repo** (HashiCorp requirement): `terraform-provider-open-unifi`

## Obsolete release

The GitHub release **v0.1.0** on this repository (`open-unifi`) shipped provider
artifacts from before the split. Do not use it for Terraform Registry publish or
new installs. Use **v0.1.1+** from `terraform-provider-open-unifi` instead.

## Contract tests

Admin API ↔ provider wire-shape tests live in [`integration/provider/`](../integration/provider/)
and depend on module `github.com/lucavb/terraform-provider-open-unifi`.

For local work on both repositories, use a `go.work` file or a temporary
`replace` in `go.mod` (do not commit `replace` on `main`).
