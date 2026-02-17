# Test 47: Unwrap with AES-256 wrapping key
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-47-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "original_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-47-original-key"
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
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-47-wrapping-key"
  key_label          = "test-47-original-key"
}

resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-47-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-47-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  token     = true
  sensitive = true
}

check "unwrapped_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Unwrapped key should be a secret key"
  }
}

check "unwrapped_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.key_type == "CKK_AES"
    error_message = "Unwrapped key should be AES"
  }
}
