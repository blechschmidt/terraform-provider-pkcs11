# Test 51: Encrypt AES-128 data with CKM_AES_ECB
resource "pkcs11_symmetric_key" "aes_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-51-aes-key"
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
  key_label  = "test-51-aes-key"
  plaintext  = base64encode("0123456789abcdef") # 16 bytes for AES block
}

check "encrypt_produces_output" {
  assert {
    condition     = data.pkcs11_encrypt.encrypted.ciphertext != ""
    error_message = "AES ECB encryption should produce non-empty ciphertext"
  }
  assert {
    condition     = data.pkcs11_encrypt.encrypted.ciphertext != data.pkcs11_encrypt.encrypted.plaintext
    error_message = "Ciphertext should differ from plaintext"
  }
}
