# Test 08: Create data object with enum string without prefix
# Validates that class can be specified without CKO_ prefix.

resource "pkcs11_object" "no_prefix" {
  class = "DATA"
  label = "test-08-no-prefix"
  value = base64encode("no prefix test")
  token = true
}

check "class_normalized" {
  assert {
    condition     = pkcs11_object.no_prefix.class == "CKO_DATA"
    error_message = "Class should be normalized to CKO_DATA"
  }
}
