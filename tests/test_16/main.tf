# Test 16: Symmetric key with encrypt-only permissions
# Validates creating a key that can only encrypt (not decrypt).

resource "pkcs11_symmetric_key" "encrypt_only" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-16-encrypt-only"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = false
  token       = true
  sensitive   = true
  extractable = false
}

check "encrypt_enabled" {
  assert {
    condition     = pkcs11_symmetric_key.encrypt_only.encrypt == true
    error_message = "Encrypt should be true"
  }
}

check "decrypt_disabled" {
  assert {
    condition     = pkcs11_symmetric_key.encrypt_only.decrypt == false
    error_message = "Decrypt should be false"
  }
}
