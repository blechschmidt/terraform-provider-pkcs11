# Test 25: RSA 3072-bit key pair
# Validates creating a larger RSA key pair.

resource "pkcs11_key_pair" "rsa3072" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    label           = "test-25-rsa3072"
    modulus_bits    = 3072
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    label    = "test-25-rsa3072"
  }
}

check "rsa3072_modulus_bits" {
  assert {
    condition     = pkcs11_key_pair.rsa3072.public_key.modulus_bits == 3072
    error_message = "RSA key should have 3072-bit modulus"
  }
}
