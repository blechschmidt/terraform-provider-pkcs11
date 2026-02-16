# Test 14: RSA key pair with mechanism without prefix
# Validates that mechanism for key pair can be specified without CKM_ prefix.

resource "pkcs11_key_pair" "rsa_no_prefix" {
  mechanism = "RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    label           = "test-14-rsa-no-prefix"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    label    = "test-14-rsa-no-prefix"
  }
}

check "mechanism_accepted" {
  assert {
    condition     = pkcs11_key_pair.rsa_no_prefix.mechanism == "RSA_PKCS_KEY_PAIR_GEN"
    error_message = "Mechanism should accept prefix-less value RSA_PKCS_KEY_PAIR_GEN"
  }
}
