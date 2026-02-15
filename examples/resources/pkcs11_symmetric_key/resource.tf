data "pkcs11_constants" "constants" {}

# Generate a 256-bit AES key
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "my-aes-key"
  class       = data.pkcs11_constants.constants.all["CKO_SECRET_KEY"]
  key_type    = data.pkcs11_constants.constants.all["CKK_AES"]
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}
