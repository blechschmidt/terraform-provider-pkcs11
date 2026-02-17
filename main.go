package main

import (
	"context"
	"flag"
	"log"

	"blechschmidt.io/terraform-provider-pkcs11/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var version = "v0.0.4-pre"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	defer provider.RunCleanup()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/blechschmidt/pkcs11",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Println(err.Error())
	}
}
