# Test 45: Verify unwrapped key gets the label from the template
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-45-wrapping-key"
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
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-45-wrapping-key"
  key_label          = "test-45-original-key"
}

resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-45-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-45-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  token     = true
  sensitive = true
}

check "unwrapped_label" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.label == "test-45-unwrapped-key"
    error_message = "Unwrapped key should have the label from the template"
  }
}
