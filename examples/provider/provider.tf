# Connect using a slot ID
provider "pkcs11" {
  module_path = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  slot_id     = 0
  pin         = var.pkcs11_pin
}

# Connect using a token label
provider "pkcs11" {
  module_path = "/usr/lib/softhsm/libsofthsm2.so"
  token_label = "MyToken"
  pin         = var.pkcs11_pin
}

# Connect using serial number and manufacturer
provider "pkcs11" {
  module_path        = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  serial_number      = "0123456789"
  token_manufacturer = "Yubico"
  pin                = var.pkcs11_pin
}

# YubiHSM with custom environment
provider "pkcs11" {
  module_path = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  slot_id     = 0
  pin         = var.pkcs11_pin
  env = {
    "YUBIHSM_PKCS11_CONF" = "/etc/yubihsm_pkcs11.conf"
  }
}
