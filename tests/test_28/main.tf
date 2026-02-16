# Test 28: Data source lookup of a symmetric key
# Validates looking up a symmetric key via the object data source.

resource "pkcs11_symmetric_key" "for_lookup" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-28-key-lookup"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

data "pkcs11_object" "key_lookup" {
  depends_on = [pkcs11_symmetric_key.for_lookup]
  label      = "test-28-key-lookup"
  class      = "CKO_SECRET_KEY"
}

check "key_found" {
  assert {
    condition     = data.pkcs11_object.key_lookup.label == "test-28-key-lookup"
    error_message = "Should find the symmetric key by label and class"
  }
}

check "key_type_correct" {
  assert {
    condition     = data.pkcs11_object.key_lookup.key_type == "CKK_AES"
    error_message = "Looked-up key should have type CKK_AES"
  }
}
