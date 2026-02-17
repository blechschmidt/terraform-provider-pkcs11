# Test 34: Verify wrapped_key_material is non-empty and ID format
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "test-34-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES128_CCM_WRAP"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "target_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-34-target-key"
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
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_symmetric_key.target_key]
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-34-wrapping-key"
  key_label          = "test-34-target-key"
}

check "material_not_empty" {
  assert {
    condition     = length(pkcs11_wrapped_key.wrapped.wrapped_key_material) > 0
    error_message = "Wrapped key material should be non-empty"
  }
}

check "id_not_empty" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped.id != ""
    error_message = "Wrapped key should have a non-empty ID"
  }
}
