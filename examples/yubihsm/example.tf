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
  env = {
    "YUBIHSM_PKCS11_CONF" : "/etc/yubihsm_pkcs11.conf"
  }
}

# Query token information
data "pkcs11_token_info" "current" {}

# List supported mechanisms
data "pkcs11_mechanisms" "all" {}

resource "pkcs11_object" "my_data" {
  class = "CKO_DATA"
  label = "my-object"
  value = base64encode("hello word")
}

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
    public_exponent = "010001" # 65537 (in base64)
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

data "pkcs11_object" "my_data" {
  label  = "my-object"
  exists = false # Do not error if the object is not found
}

output "mechanisms" {
  value = data.pkcs11_mechanisms.all
}

output "token_info" {
  value = data.pkcs11_token_info.current
}

output "data" {
  value = data.pkcs11_object.my_data
}
