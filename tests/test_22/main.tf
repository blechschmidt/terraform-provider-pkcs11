# Test 22: AES key as session object (token=false)
# Validates creating a session-only key that does not persist.

resource "pkcs11_symmetric_key" "session_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-22-session-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = false
  sensitive   = true
  extractable = false
}

check "session_key_not_token" {
  assert {
    condition     = pkcs11_symmetric_key.session_key.token == false
    error_message = "Session key should have token=false"
  }
}
