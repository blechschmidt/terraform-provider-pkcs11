# Test 59: Encrypt + decrypt round-trip with AES-256 key
resource "pkcs11_symmetric_key" "aes256_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-59-aes256-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

data "pkcs11_encrypt" "encrypted" {
  depends_on = [pkcs11_symmetric_key.aes256_key]
  mechanism  = "CKM_AES_ECB"
  key_label  = "test-59-aes256-key"
  plaintext  = base64encode("0123456789abcdef") # 16 bytes
}

data "pkcs11_decrypt" "decrypted" {
  depends_on = [data.pkcs11_encrypt.encrypted]
  mechanism  = "CKM_AES_ECB"
  key_label  = "test-59-aes256-key"
  ciphertext = data.pkcs11_encrypt.encrypted.ciphertext
}

check "aes256_round_trip" {
  assert {
    condition     = data.pkcs11_decrypt.decrypted.plaintext == data.pkcs11_encrypt.encrypted.plaintext
    error_message = "AES-256 ECB round-trip should preserve plaintext"
  }
}
