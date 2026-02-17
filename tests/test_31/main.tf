# Test 31: Basic wrap — AES key with AES wrapping key (CKM_AES_KEY_WRAP)
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-31-wrapping-key"
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
  label       = "test-31-target-key"
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
  wrapping_key_label = "test-31-wrapping-key"
  key_label          = "test-31-target-key"
}

check "basic_wrap_works" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped.wrapped_key_material != ""
    error_message = "Basic AES wrapping should produce non-empty material"
  }
}
