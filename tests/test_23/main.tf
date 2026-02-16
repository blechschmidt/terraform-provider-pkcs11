# Test 23: Extractable symmetric key
# Validates creating an extractable key.

resource "pkcs11_symmetric_key" "extractable" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-23-extractable"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = false
  extractable = true
}

check "key_extractable" {
  assert {
    condition     = pkcs11_symmetric_key.extractable.extractable == true
    error_message = "Key should be extractable"
  }
}

check "key_not_sensitive" {
  assert {
    condition     = pkcs11_symmetric_key.extractable.sensitive == false
    error_message = "Key should not be sensitive"
  }
}
