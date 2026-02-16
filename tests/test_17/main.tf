# Test 17: Symmetric key with wrap/unwrap capabilities
# Validates creating a wrapping key.

resource "pkcs11_symmetric_key" "wrap_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-17-wrap-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  wrap        = true
  unwrap      = true
  token       = true
  sensitive   = true
  extractable = false
}

check "wrap_enabled" {
  assert {
    condition     = pkcs11_symmetric_key.wrap_key.wrap == true
    error_message = "Wrap should be true"
  }
}

check "unwrap_enabled" {
  assert {
    condition     = pkcs11_symmetric_key.wrap_key.unwrap == true
    error_message = "Unwrap should be true"
  }
}
