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
