# Test 50: Round-trip verify attributes — wrap AES-128, unwrap, check all attributes
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-50-wrapping-key"
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
  label       = "test-50-original-key"
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
  wrapping_key_label = "test-50-wrapping-key"
  key_label          = "test-50-original-key"
}

resource "pkcs11_unwrapped_key" "unwrapped" {
  depends_on           = [pkcs11_wrapped_key.wrapped]
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "test-50-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped.wrapped_key_material

  label     = "test-50-unwrapped-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  encrypt   = true
  decrypt   = true
  token     = true
  sensitive = true
}

check "roundtrip_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Round-trip: class should be CKO_SECRET_KEY"
  }
}

check "roundtrip_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.key_type == "CKK_AES"
    error_message = "Round-trip: key_type should be CKK_AES"
  }
}

check "roundtrip_encrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.encrypt == true
    error_message = "Round-trip: encrypt should be true"
  }
}

check "roundtrip_decrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.decrypt == true
    error_message = "Round-trip: decrypt should be true"
  }
}
