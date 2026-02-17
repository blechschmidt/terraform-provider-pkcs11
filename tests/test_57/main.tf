# Test 57: Encrypt using prefix-less mechanism name (AES_ECB)
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-57-aes-key"
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
  mechanism  = "AES_ECB"
  key_label  = "test-57-aes-key"
  plaintext  = base64encode("0123456789abcdef")
}

check "prefixless_mechanism_works" {
  assert {
    condition     = data.pkcs11_encrypt.encrypted.ciphertext != ""
    error_message = "Encryption with prefix-less mechanism name should work"
  }
}
