# Test 35: Wrap two different keys with same wrapping key
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-35-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "target_key_a" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-35-target-a"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_symmetric_key" "target_key_b" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-35-target-b"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_wrapped_key" "wrapped_a" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.target_key_a]
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-35-wrapping-key"
  key_label          = "test-35-target-a"
}

resource "pkcs11_wrapped_key" "wrapped_b" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.target_key_b]
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-35-wrapping-key"
  key_label          = "test-35-target-b"
}

check "both_wrapped" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped_a.wrapped_key_material != "" && pkcs11_wrapped_key.wrapped_b.wrapped_key_material != ""
    error_message = "Both keys should be wrapped successfully"
  }
}
