# Test 06: Object data source with exists=false for missing object
# Validates that exists=false does not error when object is not found.

data "pkcs11_object" "missing" {
  label  = "test-06-nonexistent-object"
  class  = "CKO_DATA"
  exists = false
}

check "missing_object_not_found" {
  assert {
    condition     = data.pkcs11_object.missing.exists == false
    error_message = "exists should be false for missing object"
  }
}
