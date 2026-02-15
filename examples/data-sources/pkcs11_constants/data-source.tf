# Retrieve all PKCS#11 constant values for use in resource configuration
data "pkcs11_constants" "constants" {}

output "aes_key_type" {
  value = data.pkcs11_constants.constants.all["CKK_AES"]
}
