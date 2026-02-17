# Test 60: Encrypt/decrypt round-trip with CKM_AES_CBC and IV
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-60-aes-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

locals {
  iv = base64encode("abcdefghijklmnop")
}

data "pkcs11_encrypt" "encrypted" {
  depends_on          = [pkcs11_symmetric_key.aes_key]
  mechanism           = "CKM_AES_CBC"
  key_label           = "test-60-aes-key"
  mechanism_parameter = local.iv
  plaintext           = base64encode("0123456789abcdef") # exactly 16 bytes, no padding needed
}

data "pkcs11_decrypt" "decrypted" {
  depends_on          = [data.pkcs11_encrypt.encrypted]
  mechanism           = "CKM_AES_CBC"
  key_label           = "test-60-aes-key"
  mechanism_parameter = local.iv
  ciphertext          = data.pkcs11_encrypt.encrypted.ciphertext
}

check "aes_cbc_round_trip" {
  assert {
    condition     = data.pkcs11_decrypt.decrypted.plaintext == data.pkcs11_encrypt.encrypted.plaintext
    error_message = "AES CBC round-trip should preserve plaintext"
  }
}
