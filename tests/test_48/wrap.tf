# Phase 1: Create wrapping key, two target keys, and wrap both
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "test-48-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES128_CCM_WRAP"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "key_a" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-48-key-a"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_symmetric_key" "key_b" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-48-key-b"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_wrapped_key" "wrapped_a" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.key_a]
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-48-wrapping-key"
  key_label          = "test-48-key-a"
}

resource "pkcs11_wrapped_key" "wrapped_b" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.key_b]
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-48-wrapping-key"
  key_label          = "test-48-key-b"
}

output "wrapped_a" {
  value     = pkcs11_wrapped_key.wrapped_a.wrapped_key_material
  sensitive = true
}

output "wrapped_b" {
  value     = pkcs11_wrapped_key.wrapped_b.wrapped_key_material
  sensitive = true
}
