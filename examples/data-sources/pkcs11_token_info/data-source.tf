# Read token information from the configured slot
data "pkcs11_token_info" "current" {}

output "token_label" {
  value = data.pkcs11_token_info.current.label
}

output "token_model" {
  value = data.pkcs11_token_info.current.model
}
