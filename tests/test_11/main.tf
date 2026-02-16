# Test 11: Symmetric key with mechanism name without prefix
# Validates that mechanism can be specified without CKM_ prefix.

resource "pkcs11_symmetric_key" "no_prefix_mech" {
  mechanism   = "AES_KEY_GEN"
  label       = "test-11-no-prefix-mech"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

check "mechanism_accepted" {
  assert {
    condition     = pkcs11_symmetric_key.no_prefix_mech.mechanism == "AES_KEY_GEN"
    error_message = "Mechanism should accept prefix-less value AES_KEY_GEN"
  }
}
