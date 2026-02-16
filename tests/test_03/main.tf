# Test 03: Slots data source
# Validates that the provider can list available slots.

data "pkcs11_slots" "all" {}

output "slot_count" {
  value = length(data.pkcs11_slots.all.slots)
}

check "slots_not_empty" {
  assert {
    condition     = length(data.pkcs11_slots.all.slots) > 0
    error_message = "Slots list should not be empty"
  }
}
