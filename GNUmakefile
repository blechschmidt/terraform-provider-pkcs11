default: build

build:
	CGO_ENABLED=1 go build -o terraform-provider-pkcs11

install: build
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/blechschmidt/pkcs11/0.1.0/linux_amd64
	cp terraform-provider-pkcs11 ~/.terraform.d/plugins/registry.terraform.io/blechschmidt/pkcs11/0.1.0/linux_amd64/

test:
	CGO_ENABLED=1 go test ./... -v -count=1

testacc:
	CGO_ENABLED=1 TF_ACC=1 go test ./... -v -count=1 -timeout 120m

lint:
	golangci-lint run ./...

generate:
	go generate ./...

.PHONY: default build install test testacc lint generate
