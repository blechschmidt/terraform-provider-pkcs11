# Test 20: Object data source lookup by label and class
# Validates looking up an object using multiple filter attributes.

resource "pkcs11_object" "target" {
  class = "CKO_DATA"
  label = "test-20-lookup-target"
  value = base64encode("lookup target")
  token = true
}

data "pkcs11_object" "found" {
  depends_on = [pkcs11_object.target]
  label      = "test-20-lookup-target"
  class      = "CKO_DATA"
}

check "lookup_matches" {
  assert {
    condition     = data.pkcs11_object.found.label == pkcs11_object.target.label
    error_message = "Looked-up object label should match resource label"
  }
}

check "lookup_class" {
  assert {
    condition     = data.pkcs11_object.found.class == "CKO_DATA"
    error_message = "Looked-up object class should be CKO_DATA"
  }
}
