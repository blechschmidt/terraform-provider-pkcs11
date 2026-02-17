# Phase 1: Create wrapping key, target key, and wrap
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "test-45-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES128_CCM_WRAP"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "original_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-45-original-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_wrapped_key" "wrapped" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.original_key]
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-45-wrapping-key"
  key_label          = "test-45-original-key"
}

output "wrapped_key_material" {
  value     = pkcs11_wrapped_key.wrapped.wrapped_key_material
  sensitive = true
}
