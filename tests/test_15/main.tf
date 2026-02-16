# Test 15: RSA key pair with enum strings without prefixes
# Validates that key_type and class in nested blocks accept values without prefix.

resource "pkcs11_key_pair" "rsa_enum_no_prefix" {
  mechanism = "RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "RSA"
    class           = "PUBLIC_KEY"
    token           = true
    verify          = true
    label           = "test-15-enum-no-prefix"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "RSA"
    class    = "PRIVATE_KEY"
    token    = true
    sign     = true
    label    = "test-15-enum-no-prefix"
  }
}

check "pub_class_accepted" {
  assert {
    condition     = pkcs11_key_pair.rsa_enum_no_prefix.public_key.class == "PUBLIC_KEY"
    error_message = "Public key class should accept prefix-less value PUBLIC_KEY"
  }
}

check "priv_class_accepted" {
  assert {
    condition     = pkcs11_key_pair.rsa_enum_no_prefix.private_key.class == "PRIVATE_KEY"
    error_message = "Private key class should accept prefix-less value PRIVATE_KEY"
  }
}
