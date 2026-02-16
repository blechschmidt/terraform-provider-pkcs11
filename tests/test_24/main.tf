# Test 24: Data object lookup with exists=true (default behavior)
# Validates that exists=true succeeds when the object is found.

resource "pkcs11_object" "for_strict_lookup" {
  class = "CKO_DATA"
  label = "test-24-strict-lookup-unique"
  value = base64encode("exists true test")
  token = true
}

data "pkcs11_object" "strict_lookup" {
  depends_on = [pkcs11_object.for_strict_lookup]
  label      = "test-24-strict-lookup-unique"
  class      = "CKO_DATA"
  exists     = true
}

check "strict_lookup_exists" {
  assert {
    condition     = data.pkcs11_object.strict_lookup.exists == true
    error_message = "exists should be true for found object"
  }
}
