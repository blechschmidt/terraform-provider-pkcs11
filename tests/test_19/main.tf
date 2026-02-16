# Test 19: Multiple data objects
# Validates creating multiple objects in a single configuration.

resource "pkcs11_object" "first" {
  class = "CKO_DATA"
  label = "test-19-first"
  value = base64encode("first object")
  token = true
}

resource "pkcs11_object" "second" {
  class = "CKO_DATA"
  label = "test-19-second"
  value = base64encode("second object")
  token = true
}

resource "pkcs11_object" "third" {
  class = "CKO_DATA"
  label = "test-19-third"
  value = base64encode("third object")
  token = true
}

check "all_objects_created" {
  assert {
    condition     = pkcs11_object.first.label == "test-19-first" && pkcs11_object.second.label == "test-19-second" && pkcs11_object.third.label == "test-19-third"
    error_message = "All three objects should be created with correct labels"
  }
}
