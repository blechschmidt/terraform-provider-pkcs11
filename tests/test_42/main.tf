# Test 42: Verify unwrapped AES-256 key attributes
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-42-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "original_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-42-original-key"
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
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.original_key]
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-42-wrapping-key"
  key_label          = "test-42-original-key"
}

resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-42-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-42-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  encrypt   = true
  decrypt   = true
  token     = true
  sensitive = true
}

check "unwrapped_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.key_type == "CKK_AES"
    error_message = "Unwrapped key should be AES"
  }
}

check "unwrapped_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Unwrapped key should be a secret key"
  }
}
