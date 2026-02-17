# Encrypt data with AES-ECB (input must be a multiple of 16 bytes)
data "pkcs11_encrypt" "example" {
  mechanism = "CKM_AES_ECB"
  key_label = "my-aes-key"
  plaintext = base64encode("0123456789abcdef")
}

output "ciphertext" {
  value     = data.pkcs11_encrypt.example.ciphertext
  sensitive = true
}

# Encrypt with AES-CBC using an IV
data "pkcs11_encrypt" "cbc" {
  mechanism           = "CKM_AES_CBC_PAD"
  key_label           = "my-aes-key"
  mechanism_parameter = base64encode("0123456789abcdef") # 16-byte IV
  plaintext           = base64encode("hello world")
}
