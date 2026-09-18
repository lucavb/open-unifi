# Local development setup for the open-unifi provider

`cmd/tfprovider` serves the provider over the terraform plugin protocol
(tfplugin6, Terraform >= 1.6). Because nightly iteration happens before any
registry release, use Terraform's *filesystem mirror* development override
(modern local-dev naming:

    dev.open-unifi/lucavb/open-unifi

## 1. Build and stage the provider binary

```sh
GOFLAGS=-buildvcs=false go build -o terraform-provider-open-unifi_v0.0.1 ./cmd/tfprovider

MIRROR="${HOME}/.terraform.d/plugins/dev.open-unifi/lucavb/open-unifi/0.0.1/darwin_arm64"
mkdir -p "$MIRROR"
mv terraform-provider-open-unifi_v0.0.1 "$MIRROR/"
```

(`0.0.1` is an arbitrary local hour version; bump it when the schema
changes so Terraform re-installs. Adjust `darwin_arm64` for your host.)

## 2. Development override

Put this in `~/.terraformrc` (Linux) or
`~/Library/Application Support/terraform.rc` (macOS):

```hcl
provider_installation {
  dev_overrides {
    # "lucavb/open-unifi" is resolved from this local mirror directory:
    registry.terraform.io/lucavb/open-unifi = "$HOME/.terraform.d/plugins"
  }
  # dev_overrides have no implicit registry fallback:
  direct {
    exclude = ["registry.terraform.io/lucavb/open-unifi"]
  }
}
```

With `dev_overrides`, you skip `terraform init` entirely: run
`terraform plan` / `apply` directly; Terraform finds the mirror instead of
querying the registry.

## 3. Point the provider at your controller

Set `url` (Required), optionally `token` (keep secrets out of .tf — prefer
the `OPEN_UNIFI_ADMIN_TOKEN` env var, which `provider.Configure` reads when
`token` is unset). The controller serves **plain HTTP** on its admin port
(default `:8443`); there is no TLS yet, so use `url = "http://<host>:8443"` —
self-signed-certificate guidance does not apply. If you need TLS today,
front-load it with a reverse proxy that terminates HTTPS and forwards to the
plain-HTTP admin listener. (`insecure_skip_verify` only affects `https://`
URLs and can stay unset.)

## 4. Run

```sh
cd examples/terraform
terraform plan    # no init needed under dev_overrides
terraform apply
```

See `main.tf` in this directory for a full walkthrough example.
