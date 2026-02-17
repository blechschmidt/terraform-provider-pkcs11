# Test 54: Encrypt with explicit key_class = CKO_SECRET_KEY
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-54-aes-key"
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
  key_label  = "test-54-aes-key"
  key_class  = "CKO_SECRET_KEY"
  plaintext  = base64encode("0123456789abcdef")
}

check "explicit_class_works" {
  assert {
    condition     = data.pkcs11_encrypt.encrypted.ciphertext != ""
    error_message = "Encryption with explicit key_class should produce output"
  }
}
