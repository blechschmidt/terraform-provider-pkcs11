# Test 40: Wrap with AES-256 wrapping key and AES-256 target
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "test-40-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES256_CCM_WRAP"
  value_len   = 32
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "target_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-40-target-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_wrapped_key" "wrapped" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.target_key]
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-40-wrapping-key"
  key_label          = "test-40-target-key"
}

check "aes256_wrap_works" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped.wrapped_key_material != ""
    error_message = "Wrapping AES-256 key with AES-256 wrapping key should produce material"
  }
}
