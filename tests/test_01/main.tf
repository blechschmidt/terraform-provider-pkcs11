# Test 01: Token info data source
# Validates that the provider can connect and read token information.

data "pkcs11_token_info" "current" {}

output "token_label" {
  value = data.pkcs11_token_info.current.label
}

output "token_model" {
  value = data.pkcs11_token_info.current.model
}

check "token_info_populated" {
  assert {
    condition     = data.pkcs11_token_info.current.label != ""
    error_message = "Token label should not be empty"
  }
}
