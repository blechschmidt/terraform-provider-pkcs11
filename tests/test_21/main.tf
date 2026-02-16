# Test 21: RSA key pair with sign-only private key
# Validates creating an RSA key pair where private key can only sign (not decrypt).

resource "pkcs11_key_pair" "sign_only" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    label           = "test-21-sign-only"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    decrypt  = false
    label    = "test-21-sign-only"
  }
}

check "private_key_sign" {
  assert {
    condition     = pkcs11_key_pair.sign_only.private_key.sign == true
    error_message = "Private key should have sign capability"
  }
}
