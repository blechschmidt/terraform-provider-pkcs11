# Test 58: Sign with explicit key_class = CKO_PRIVATE_KEY
resource "pkcs11_key_pair" "rsa_key" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    label        = "test-58-rsa-pub"
    class        = "CKO_PUBLIC_KEY"
    key_type     = "CKK_RSA"
    modulus_bits = 2048
    token        = true
    verify       = true
  }

  private_key = {
    label       = "test-58-rsa-priv"
    class       = "CKO_PRIVATE_KEY"
    key_type    = "CKK_RSA"
    token       = true
    sign        = true
    sensitive   = true
    extractable = false
  }
}

data "pkcs11_signature" "sig" {
  depends_on = [pkcs11_key_pair.rsa_key]
  mechanism  = "CKM_SHA256_RSA_PKCS"
  key_label  = "test-58-rsa-priv"
  key_class  = "CKO_PRIVATE_KEY"
  data       = base64encode("Test message for signing")
}

check "explicit_private_key_class" {
  assert {
    condition     = data.pkcs11_signature.sig.signature != ""
    error_message = "Signing with explicit CKO_PRIVATE_KEY class should work"
  }
}
