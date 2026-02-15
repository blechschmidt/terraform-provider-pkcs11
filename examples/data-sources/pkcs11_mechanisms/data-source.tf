# List all mechanisms supported by the token
data "pkcs11_mechanisms" "all" {}

output "supported_mechanisms" {
  value = data.pkcs11_mechanisms.all.mechanisms
}
