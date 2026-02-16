# Test 02: Mechanisms data source
# Validates that the provider can list supported mechanisms.

data "pkcs11_mechanisms" "all" {}

output "mechanism_count" {
  value = length(data.pkcs11_mechanisms.all.mechanisms)
}

check "mechanisms_not_empty" {
  assert {
    condition     = length(data.pkcs11_mechanisms.all.mechanisms) > 0
    error_message = "Mechanisms list should not be empty"
  }
}
