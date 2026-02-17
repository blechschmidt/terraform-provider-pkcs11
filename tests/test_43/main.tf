# Test 43: Unwrap with explicit unwrapping_key_class
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-43-wrapping-key"
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
  label       = "test-43-original-key"
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
  wrapping_key_label = "test-43-wrapping-key"
  key_label          = "test-43-original-key"
}

resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-43-wrapping-key"
  unwrapping_key_class = "CKO_SECRET_KEY"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-43-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  token     = true
  sensitive = true
}

check "unwrapping_key_class_preserved" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.unwrapping_key_class == "CKO_SECRET_KEY"
    error_message = "unwrapping_key_class should be preserved as CKO_SECRET_KEY"
  }
}
