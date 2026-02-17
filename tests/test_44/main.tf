# Test 44: Unwrap using prefix-less mechanism and class names
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "AES_KEY_GEN"
  label       = "test-44-wrapping-key"
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
  mechanism   = "AES_KEY_GEN"
  label       = "test-44-original-key"
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
  mechanism          = "AES_KEY_WRAP"
  wrapping_key_label = "test-44-wrapping-key"
  key_label          = "test-44-original-key"
}

# Uses prefix-less names: "AES_KEY_WRAP" and "SECRET_KEY"
resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "AES_KEY_WRAP"
  unwrapping_key_label = "test-44-wrapping-key"
  unwrapping_key_class = "SECRET_KEY"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-44-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  token     = true
  sensitive = true
}

check "unwrapped_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Unwrapped key should be a secret key (class normalizes to CKO_ prefix)"
  }
}
