# Test 17: AES 192-bit symmetric key
# Validates creating an AES key with a different key size (192-bit).

resource "pkcs11_symmetric_key" "aes192" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-17-aes192"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 24
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

check "aes192_value_len" {
  assert {
    condition     = pkcs11_symmetric_key.aes192.value_len == 24
    error_message = "AES-192 key should have value_len 24"
  }
}

check "aes192_label" {
  assert {
    condition     = pkcs11_symmetric_key.aes192.label == "test-17-aes192"
    error_message = "Label should match"
  }
}
