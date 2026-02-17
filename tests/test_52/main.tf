# Test 52: Encrypt then decrypt round-trip with AES ECB
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-52-aes-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

data "pkcs11_encrypt" "encrypted" {
  depends_on = [pkcs11_symmetric_key.aes_key]
  mechanism  = "CKM_AES_ECB"
  key_label  = "test-52-aes-key"
  plaintext  = base64encode("0123456789abcdef")
}

data "pkcs11_decrypt" "decrypted" {
  depends_on = [data.pkcs11_encrypt.encrypted]
  mechanism  = "CKM_AES_ECB"
  key_label  = "test-52-aes-key"
  ciphertext = data.pkcs11_encrypt.encrypted.ciphertext
}

check "round_trip_works" {
  assert {
    condition     = data.pkcs11_decrypt.decrypted.plaintext == data.pkcs11_encrypt.encrypted.plaintext
    error_message = "Decrypted plaintext should match original plaintext"
  }
}
