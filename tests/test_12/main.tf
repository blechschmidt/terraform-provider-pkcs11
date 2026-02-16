# Test 12: Symmetric key with enum strings without prefixes
# Validates that class and key_type can be specified without prefixes.

resource "pkcs11_symmetric_key" "enum_no_prefix" {
  mechanism   = "AES_KEY_GEN"
  label       = "test-12-enum-no-prefix"
  class       = "SECRET_KEY"
  key_type    = "AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

check "class_accepted" {
  assert {
    condition     = pkcs11_symmetric_key.enum_no_prefix.class == "SECRET_KEY"
    error_message = "Class should accept prefix-less value SECRET_KEY"
  }
}

check "key_type_accepted" {
  assert {
    condition     = pkcs11_symmetric_key.enum_no_prefix.key_type == "AES"
    error_message = "Key type should accept prefix-less value AES"
  }
}
