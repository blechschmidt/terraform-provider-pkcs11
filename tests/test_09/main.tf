# Test 09: AES 256-bit symmetric key generation
# Validates creating an AES key with CKM_AES_KEY_GEN.

resource "pkcs11_symmetric_key" "aes256" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-09-aes256"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

check "aes_key_label" {
  assert {
    condition     = pkcs11_symmetric_key.aes256.label == "test-09-aes256"
    error_message = "AES key label should match"
  }
}

check "aes_key_type" {
  assert {
    condition     = pkcs11_symmetric_key.aes256.key_type == "CKK_AES"
    error_message = "Key type should be CKK_AES"
  }
}
