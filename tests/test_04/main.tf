# Test 04: Constants data source
# Validates that the provider exposes PKCS#11 constant mappings.

data "pkcs11_constants" "all" {}

output "constant_count" {
  value = length(data.pkcs11_constants.all.all)
}

check "constants_not_empty" {
  assert {
    condition     = length(data.pkcs11_constants.all.all) > 0
    error_message = "Constants map should not be empty"
  }
}

check "has_cko_data" {
  assert {
    condition     = lookup(data.pkcs11_constants.all.all, "CKO_DATA", null) != null
    error_message = "Constants should contain CKO_DATA"
  }
}
