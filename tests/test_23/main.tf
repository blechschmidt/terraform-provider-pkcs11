# Test 23: Data object value round-trip
# Validates that a data object's value survives a create/read cycle.

resource "pkcs11_object" "roundtrip" {
  class = "CKO_DATA"
  label = "test-23-roundtrip"
  value = base64encode("round trip test data")
  token = true
}

data "pkcs11_object" "readback" {
  depends_on = [pkcs11_object.roundtrip]
  label      = "test-23-roundtrip"
  class      = "CKO_DATA"
}

check "value_matches" {
  assert {
    condition     = data.pkcs11_object.readback.value == base64encode("round trip test data")
    error_message = "Value should match after round-trip"
  }
}

check "class_matches" {
  assert {
    condition     = data.pkcs11_object.readback.class == "CKO_DATA"
    error_message = "Class should be CKO_DATA"
  }
}
