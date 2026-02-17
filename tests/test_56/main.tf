# Test 56: Encrypt/decrypt round-trip with CKM_AES_CBC_PAD and IV
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-56-aes-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

# 16-byte IV for AES CBC
locals {
  iv = base64encode("1234567890abcdef")
}

data "pkcs11_encrypt" "encrypted" {
  depends_on          = [pkcs11_symmetric_key.aes_key]
  mechanism           = "CKM_AES_CBC_PAD"
  key_label           = "test-56-aes-key"
  mechanism_parameter = local.iv
  plaintext           = base64encode("Hello World from PKCS11!")
}

data "pkcs11_decrypt" "decrypted" {
  depends_on          = [data.pkcs11_encrypt.encrypted]
  mechanism           = "CKM_AES_CBC_PAD"
  key_label           = "test-56-aes-key"
  mechanism_parameter = local.iv
  ciphertext          = data.pkcs11_encrypt.encrypted.ciphertext
}

check "cbc_pad_round_trip" {
  assert {
    condition     = data.pkcs11_decrypt.decrypted.plaintext == data.pkcs11_encrypt.encrypted.plaintext
    error_message = "AES CBC PAD round-trip should preserve plaintext"
  }
}
