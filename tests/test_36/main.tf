# Test 36: Wrap using prefix-less mechanism name
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "AES_KEY_GEN"
  label       = "test-36-wrapping-key"
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
  mechanism   = "AES_KEY_GEN"
  label       = "test-36-target-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

# Use prefix-less mechanism name
resource "pkcs11_wrapped_key" "wrapped" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.target_key]
  mechanism          = "AES_KEY_WRAP"
  wrapping_key_label = "test-36-wrapping-key"
  key_label          = "test-36-target-key"
}

check "prefix_less_mechanism_works" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped.wrapped_key_material != ""
    error_message = "Wrapping with prefix-less mechanism name should work"
  }
}
