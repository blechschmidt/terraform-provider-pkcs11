# List all available PKCS#11 slots
data "pkcs11_slots" "all" {}

# List only slots with a token present
data "pkcs11_slots" "with_token" {
  token_present = true
}

output "available_slots" {
  value = data.pkcs11_slots.with_token.slots
}
