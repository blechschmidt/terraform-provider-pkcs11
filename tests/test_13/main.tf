# Test 13: RSA 2048-bit key pair generation
# Validates creating an RSA key pair for signing/verification.

resource "pkcs11_key_pair" "rsa2048" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    encrypt         = true
    label           = "test-13-rsa2048"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    decrypt  = true
    label    = "test-13-rsa2048"
  }
}

check "public_key_label" {
  assert {
    condition     = pkcs11_key_pair.rsa2048.public_key.label == "test-13-rsa2048"
    error_message = "Public key label should match"
  }
}

check "private_key_label" {
  assert {
    condition     = pkcs11_key_pair.rsa2048.private_key.label == "test-13-rsa2048"
    error_message = "Private key label should match"
  }
}
