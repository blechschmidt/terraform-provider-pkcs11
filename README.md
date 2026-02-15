# Terraform Provider for PKCS#11

A Terraform provider for managing cryptographic objects (keys, certificates, data) on PKCS#11 tokens and HSMs.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.25 (for building)
- A PKCS#11 module (e.g., [SoftHSM2](https://www.opendnssec.org/softhsm/), YubiHSM, Thales Luna, AWS CloudHSM)
- CGO enabled (`CGO_ENABLED=1`)

## Building

```bash
go build ./...
```

## Installation (local development)

Add a `dev_overrides` block to your `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "blechschmidt/pkcs11" = "/path/to/your/binary"
  }
  direct {}
}
```

## Provider Configuration

```hcl
provider "pkcs11" {
  module_path = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  slot_id     = 0
  pin         = var.pkcs11_pin
}
```

| Attribute     | Env Var              | Description                                      |
|---------------|----------------------|--------------------------------------------------|
| `module_path` | `PKCS11_MODULE_PATH` | Path to the PKCS#11 shared library (required)    |
| `token_label` | `PKCS11_TOKEN_LABEL` | Token label (mutually exclusive with `slot_id`)  |
| `slot_id`     | `PKCS11_SLOT_ID`     | Slot ID (mutually exclusive with `token_label`)  |
| `pin`         | `PKCS11_PIN`         | User PIN for login                               |
| `so_pin`      | `PKCS11_SO_PIN`      | Security Officer PIN                             |

## Resources

### `pkcs11_object`

Creates a generic PKCS#11 object on the token using `C_CreateObject`. All PKCS#11 attributes (`CKA_*` constants, lower-cased without the `CKA_` prefix) can be specified directly.

### `pkcs11_key_pair`

Generates an asymmetric key pair using `C_GenerateKeyPair`. Requires a `mechanism` (e.g., `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_EC_KEY_PAIR_GEN`) and separate `public_key` and `private_key` blocks for the respective attribute templates.

### `pkcs11_symmetric_key`

Generates a symmetric key using `C_GenerateKey`. Requires a `mechanism` (e.g., `CKM_AES_KEY_GEN`, `CKM_DES3_KEY_GEN`, `CKM_GENERIC_SECRET_KEY_GEN`). All PKCS#11 attributes can be specified directly.

## Data Sources

| Data Source            | Description                                       |
|------------------------|---------------------------------------------------|
| `pkcs11_slots`         | List available slots                              |
| `pkcs11_token_info`    | Token metadata (label, model, flags)              |
| `pkcs11_mechanisms`    | Supported mechanisms and key sizes                |
| `pkcs11_object`        | Look up an object by attributes, returning all readable attributes |
| `pkcs11_constants`     | PKCS#11 constant name-to-value mappings           |

## Example Usage (YubiHSM)

```hcl
terraform {
  required_providers {
    pkcs11 = {
      source = "blechschmidt/pkcs11"
    }
  }
}

variable "pkcs11_pin" {
  type      = string
  sensitive = true
}

provider "pkcs11" {
  module_path = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  slot_id     = 0
  pin         = var.pkcs11_pin
}

data "pkcs11_constants" "constants" {}

# Create a generic data object
resource "pkcs11_object" "my_data" {
  class = data.pkcs11_constants.constants.all["CKO_DATA"]
  label = "my-object"
  value = base64encode("hello world")
}

# Generate an RSA key pair for signing
resource "pkcs11_key_pair" "signing" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = data.pkcs11_constants.constants.all["CKK_RSA"]
    class           = data.pkcs11_constants.constants.all["CKO_PUBLIC_KEY"]
    token           = true
    verify          = true
    encrypt         = true
    label           = "test-signing-key"
    modulus_bits    = 2048
    public_exponent = "010001" # 65537 in hex
  }
  private_key = {
    key_type = data.pkcs11_constants.constants.all["CKK_RSA"]
    class    = data.pkcs11_constants.constants.all["CKO_PRIVATE_KEY"]
    sign     = true
    decrypt  = true
    token    = true
    label    = "test-signing-key"
  }
}

# Generate an AES-256 symmetric key
resource "pkcs11_symmetric_key" "test_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-symmetric-key"
  class       = data.pkcs11_constants.constants.all["CKO_SECRET_KEY"]
  key_type    = data.pkcs11_constants.constants.all["CKK_AES"]
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

# Look up an object (with optional existence check)
data "pkcs11_object" "my_data" {
  label  = "my-object"
  exists = false # Do not error if the object is not found
}
```

## Attributes

All resources and the `pkcs11_object` data source use PKCS#11 attribute names with the `CKA_` prefix stripped and lower-cased. For example, `CKA_LABEL` becomes `label`, `CKA_KEY_TYPE` becomes `key_type`, etc.

### Type Encoding

| PKCS#11 Type     | Terraform Type | Encoding                          |
|------------------|----------------|-----------------------------------|
| `CK_BBOOL`       | `bool`         | Native boolean                    |
| `CK_ULONG`       | `number`       | Native integer                    |
| UTF-8 strings    | `string`       | Plain string                      |
| Byte arrays      | `string`       | Base64-encoded                    |
| Big integers     | `string`       | Hex-encoded                       |

Numeric constants (key types, object classes, mechanisms) can be looked up via the `pkcs11_constants` data source rather than hard-coding values.

## Import

### `pkcs11_object` and `pkcs11_symmetric_key`

```
terraform import pkcs11_object.example "label/key_id_hex/CKO_CLASS_NAME"
terraform import pkcs11_symmetric_key.example "label/key_id_hex/CKO_SECRET_KEY"
```

### `pkcs11_key_pair`

```
terraform import pkcs11_key_pair.example "label/key_id_hex"
```

The import finds both the public and private key by shared label and CKA_ID.

## Testing

```bash
go test ./...
go vet ./...
```

## License

MIT License. See [LICENSE](LICENSE) for details.
