# Test 05: Create and read a data object
# Validates basic object lifecycle: create, read back, verify attributes.

resource "pkcs11_object" "test_data" {
  class = "CKO_DATA"
  label = "test-05-data-object"
  value = base64encode("test data content")
  token = true
}

data "pkcs11_object" "read_back" {
  label = pkcs11_object.test_data.label
  class = "CKO_DATA"
}

check "object_exists" {
  assert {
    condition     = data.pkcs11_object.read_back.label == "test-05-data-object"
    error_message = "Read-back label should match"
  }
}
