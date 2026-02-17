# Terraform Provider for PKCS#11

A Terraform provider for managing cryptographic objects and performing cryptographic operations on PKCS#11 tokens and HSMs.

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

| Attribute            | Env Var                      | Description                                                        |
|----------------------|------------------------------|--------------------------------------------------------------------|
| `module_path`        | `PKCS11_MODULE_PATH`         | Path to the PKCS#11 shared library (required)                      |
| `token_label`        | `PKCS11_TOKEN_LABEL`         | Token label filter (combinable with other token filters)           |
| `serial_number`      | `PKCS11_SERIAL_NUMBER`       | Token serial number filter                                         |
| `token_manufacturer` | `PKCS11_TOKEN_MANUFACTURER`  | Token manufacturer filter                                          |
| `token_model`        | `PKCS11_TOKEN_MODEL`         | Token model filter                                                 |
| `slot_id`            | `PKCS11_SLOT_ID`             | Slot ID (mutually exclusive with token filters)                    |
| `pin`                | `PKCS11_PIN`                 | User PIN for login                                                 |
| `so_pin`             | `PKCS11_SO_PIN`              | Security Officer PIN                                               |

Token selection uses either `slot_id` (explicit) or one or more token filters (`token_label`, `serial_number`, `token_manufacturer`, `token_model`). When multiple filters are specified, all must match (AND logic). At least one of `slot_id` or a token filter is required.

## Resources

### `pkcs11_object`

Creates a generic PKCS#11 object on the token using `C_CreateObject`. All PKCS#11 attributes (`CKA_*` constants, lower-cased without the `CKA_` prefix) can be specified directly.

### `pkcs11_key_pair`

Generates an asymmetric key pair using `C_GenerateKeyPair`. Requires a `mechanism` and separate `public_key` and `private_key` blocks for the respective attribute templates.

### `pkcs11_symmetric_key`

Generates a symmetric key using `C_GenerateKey`. Requires a `mechanism`. All PKCS#11 attributes can be specified directly.

### `pkcs11_wrapped_key`

Wraps (exports) an existing key using `C_WrapKey`. Produces base64-encoded wrapped key material that can be stored or transferred. Requires a wrapping key label, a target key label, and a wrapping mechanism.

### `pkcs11_unwrapped_key`

Unwraps (imports) a previously wrapped key using `C_UnwrapKey`. Takes base64-encoded wrapped key material and imports it back onto the token. Requires an unwrapping key label, a mechanism, and the wrapped key material.

## Data Sources

| Data Source            | Description                                       |
|------------------------|---------------------------------------------------|
| `pkcs11_slots`         | List available slots                              |
| `pkcs11_token_info`    | Token metadata (label, model, flags)              |
| `pkcs11_mechanisms`    | Supported mechanisms and key sizes                |
| `pkcs11_object`        | Look up an object by attributes, returning all readable attributes |
| `pkcs11_constants`     | PKCS#11 constant name-to-value mappings           |
| `pkcs11_encrypt`       | Encrypt data using a key on the token (`C_Encrypt`) |
| `pkcs11_decrypt`       | Decrypt data using a key on the token (`C_Decrypt`) |
| `pkcs11_signature`     | Sign data using a key on the token (`C_Sign`)     |

## Example Usage

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

# Create a generic data object
resource "pkcs11_object" "my_data" {
  class = "CKO_DATA"
  label = "my-object"
  value = base64encode("hello world")
}

# Generate an RSA key pair for signing
resource "pkcs11_key_pair" "signing" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    encrypt         = true
    label           = "test-signing-key"
    modulus_bits    = 2048
    public_exponent = "010001" # 65537 in hex
  }
  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
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
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

# Encrypt data with AES
data "pkcs11_encrypt" "encrypted" {
  mechanism = "CKM_AES_ECB"
  key_label = "test-symmetric-key"
  plaintext = base64encode("0123456789abcdef") # must be base64-encoded
}

# Decrypt data with AES
data "pkcs11_decrypt" "decrypted" {
  mechanism  = "CKM_AES_ECB"
  key_label  = "test-symmetric-key"
  ciphertext = data.pkcs11_encrypt.encrypted.ciphertext
}

# Sign data with RSA
data "pkcs11_signature" "sig" {
  mechanism = "CKM_SHA256_RSA_PKCS"
  key_label = "test-signing-key"
  data      = base64encode("message to sign")
}

# Wrap a key for export
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "my-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES128_CCM_WRAP"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_wrapped_key" "wrapped" {
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "my-wrapping-key"
  key_label          = "test-symmetric-key"
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

### Enum Attributes

Attributes that represent PKCS#11 constants (`class`, `key_type`, `certificate_type`, `key_gen_mechanism`, `mechanism_type`) accept their values as strings. You can specify them in three ways:

- **Full constant name**: `"CKO_SECRET_KEY"`, `"CKK_AES"`, `"CKM_AES_KEY_GEN"`
- **Without prefix**: `"SECRET_KEY"`, `"AES"`, `"AES_KEY_GEN"`
- **Numeric value**: `"3"`, `"31"`

The `mechanism` attribute on resources (`pkcs11_symmetric_key`, `pkcs11_key_pair`, `pkcs11_wrapped_key`, `pkcs11_unwrapped_key`) and data sources (`pkcs11_encrypt`, `pkcs11_decrypt`, `pkcs11_signature`) also supports these formats with the `CKM_` prefix.

Values are always normalized to the canonical full name in state (e.g., `"SECRET_KEY"` becomes `"CKO_SECRET_KEY"`).

The `pkcs11_constants` data source is still available for looking up numeric values of all PKCS#11 constants.

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
