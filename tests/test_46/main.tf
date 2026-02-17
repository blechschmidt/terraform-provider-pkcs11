# Test 46: Verify encrypt/decrypt attributes from template
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-46-wrapping-key"
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
  label       = "test-46-original-key"
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
  wrapping_key_label = "test-46-wrapping-key"
  key_label          = "test-46-original-key"
}

resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-46-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-46-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  encrypt   = true
  decrypt   = true
  token     = true
  sensitive = true
}

check "unwrapped_encrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.encrypt == true
    error_message = "Unwrapped key should have encrypt = true"
  }
}

check "unwrapped_decrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.decrypt == true
    error_message = "Unwrapped key should have decrypt = true"
  }
}

check "unwrapped_sensitive" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.sensitive == true
    error_message = "Unwrapped key should have sensitive = true"
  }
}
