# Test 07: Update a data object's value
# Validates that updating an object's value works correctly.

resource "pkcs11_object" "updatable" {
  class = "CKO_DATA"
  label = "test-07-updatable"
  value = base64encode("updated content")
  token = true
}

check "object_label" {
  assert {
    condition     = pkcs11_object.updatable.label == "test-07-updatable"
    error_message = "Object label should match"
  }
}

check "object_class" {
  assert {
    condition     = pkcs11_object.updatable.class == "CKO_DATA"
    error_message = "Object class should be CKO_DATA"
  }
}
