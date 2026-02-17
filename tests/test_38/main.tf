# Test 38: Wrap key with AES-192 wrapping key
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "test-38-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES192_CCM_WRAP"
  value_len   = 24
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "target_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-38-target-key"
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
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-38-wrapping-key"
  key_label          = "test-38-target-key"
}

check "aes192_wrap_works" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped.wrapped_key_material != ""
    error_message = "AES-192 wrapping key should work"
  }
}
