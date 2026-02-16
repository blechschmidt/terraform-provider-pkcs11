# Test 10: AES 128-bit symmetric key generation
# Validates creating a smaller AES key.

resource "pkcs11_symmetric_key" "aes128" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-10-aes128"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

check "aes128_value_len" {
  assert {
    condition     = pkcs11_symmetric_key.aes128.value_len == 16
    error_message = "AES-128 key should have value_len 16"
  }
}
