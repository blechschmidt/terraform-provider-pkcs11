# Decrypt data using the same mechanism and key used for encryption
data "pkcs11_decrypt" "example" {
  mechanism  = "CKM_AES_ECB"
  key_label  = "my-aes-key"
  ciphertext = data.pkcs11_encrypt.example.ciphertext
}

output "plaintext" {
  value     = data.pkcs11_decrypt.example.plaintext
  sensitive = true
}

# Decrypt AES-CBC with IV
data "pkcs11_decrypt" "cbc" {
  mechanism           = "CKM_AES_CBC_PAD"
  key_label           = "my-aes-key"
  mechanism_parameter = base64encode("0123456789abcdef") # same IV used for encryption
  ciphertext          = data.pkcs11_encrypt.cbc.ciphertext
}
