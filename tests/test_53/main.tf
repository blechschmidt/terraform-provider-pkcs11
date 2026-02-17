# Test 53: Sign with RSA key using CKM_SHA256_RSA_PKCS
resource "pkcs11_key_pair" "rsa_key" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    label        = "test-53-rsa-pub"
    class        = "CKO_PUBLIC_KEY"
    key_type     = "CKK_RSA"
    modulus_bits = 2048
    token        = true
    verify       = true
  }

  private_key = {
    label       = "test-53-rsa-priv"
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
  key_label  = "test-53-rsa-priv"
  data       = base64encode("Hello, PKCS11!")
}

check "rsa_sign_works" {
  assert {
    condition     = data.pkcs11_signature.sig.signature != ""
    error_message = "RSA signing should produce a non-empty signature"
  }
}
