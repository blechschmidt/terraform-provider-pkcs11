# Sign data with an RSA private key
data "pkcs11_signature" "rsa" {
  mechanism = "CKM_SHA256_RSA_PKCS"
  key_label = "my-signing-key"
  data      = base64encode("message to sign")
}

output "rsa_signature" {
  value = data.pkcs11_signature.rsa.signature
}

# Sign data with an EC private key
data "pkcs11_signature" "ecdsa" {
  mechanism = "CKM_ECDSA"
  key_label = "my-ec-key"
  key_class = "CKO_PRIVATE_KEY"
  data      = base64encode("message to sign")
}
