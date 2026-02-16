# Test 30: Token info and mechanisms combined
# Validates reading both token info and mechanisms in a single configuration.

data "pkcs11_token_info" "info" {}
data "pkcs11_mechanisms" "mechs" {}
data "pkcs11_slots" "slots" {}
data "pkcs11_constants" "consts" {}

check "token_has_label" {
  assert {
    condition     = data.pkcs11_token_info.info.label != ""
    error_message = "Token should have a label"
  }
}

check "has_mechanisms" {
  assert {
    condition     = length(data.pkcs11_mechanisms.mechs.mechanisms) > 0
    error_message = "Should have at least one mechanism"
  }
}

check "has_slots" {
  assert {
    condition     = length(data.pkcs11_slots.slots.slots) > 0
    error_message = "Should have at least one slot"
  }
}

check "has_constants" {
  assert {
    condition     = length(data.pkcs11_constants.consts.constants) > 0
    error_message = "Should have constants defined"
  }
}
