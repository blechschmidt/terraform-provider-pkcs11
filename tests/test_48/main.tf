# Test 48: Unwrap two keys from different wrapped materials (single-phase)
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-48-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "key_a" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-48-key-a"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_symmetric_key" "key_b" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-48-key-b"
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
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.key_a]
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-48-wrapping-key"
  key_label          = "test-48-key-a"
}

resource "pkcs11_wrapped_key" "wrapped_b" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.key_b]
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = "test-48-wrapping-key"
  key_label          = "test-48-key-b"
}

resource "pkcs11_unwrapped_key" "unwrapped_a" {
  depends_on           = [pkcs11_wrapped_key.wrapped_a]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-48-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped_a.wrapped_key_material

  label     = "test-48-unwrapped-a"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  token     = true
  sensitive = true
}

resource "pkcs11_unwrapped_key" "unwrapped_b" {
  depends_on           = [pkcs11_wrapped_key.wrapped_b]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-48-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped_b.wrapped_key_material

  label     = "test-48-unwrapped-b"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  token     = true
  sensitive = true
}

check "both_unwrapped" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_a.class == "CKO_SECRET_KEY" && pkcs11_unwrapped_key.unwrapped_b.class == "CKO_SECRET_KEY"
    error_message = "Both keys should be unwrapped as CKO_SECRET_KEY"
  }
}

check "key_type_a" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_a.key_type == "CKK_AES"
    error_message = "Unwrapped key A should be AES"
  }
}

check "key_type_b" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_b.key_type == "CKK_AES"
    error_message = "Unwrapped key B should be AES"
  }
}
