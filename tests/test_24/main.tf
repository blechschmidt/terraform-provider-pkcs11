# Test 24: Data object lookup with exists=true (default behavior)
# Validates that exists=true errors if object is missing, and succeeds when found.

resource "pkcs11_object" "for_lookup" {
  class = "CKO_DATA"
  label = "test-24-for-lookup"
  value = base64encode("exists true test")
  token = true
}

data "pkcs11_object" "strict_lookup" {
  depends_on = [pkcs11_object.for_lookup]
  label      = "test-24-for-lookup"
  class      = "CKO_DATA"
  exists     = true
}

check "strict_lookup_exists" {
  assert {
    condition     = data.pkcs11_object.strict_lookup.exists == true
    error_message = "exists should be true for found object"
  }
}
