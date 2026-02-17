# Test 32: Wrap with explicit wrapping_key_class and key_class
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-32-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "target_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-32-target-key"
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
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.target_key]
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-32-wrapping-key"
  wrapping_key_class = "CKO_SECRET_KEY"
  key_label          = "test-32-target-key"
  key_class          = "CKO_SECRET_KEY"
}

check "explicit_classes_work" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped.wrapped_key_material != ""
    error_message = "Wrapping with explicit key classes should work"
  }
}
