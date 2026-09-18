// Command tfprovider serves the open-unifi Terraform provider over the
// terraform-plugin-protocol (tfplugin6.Serve convention, required by
// Terraform >= 1.6 for plugin signing/attestation checks).
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/lucavb/open-unifi/provider"
)

func main() {
	ctx := context.Background()

	err := providerserver.Serve(ctx, provider.New, providerserver.ServeOpts{
		// Address stanza for the built-in "local development override"
		// workflow (filesystem_mirror with
		// dev.open-unifi/lucavb/open-unifi, see examples/terraform/).
		Address: "registry.terraform.io/lucavb/open-unifi",
	})
	if err != nil {
		log.Fatalf("tfprovider: serve: %v", err)
	}
}
