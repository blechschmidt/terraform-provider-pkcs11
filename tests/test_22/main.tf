# Test 22: RSA key pair with both sign and encrypt
# Validates creating an RSA key pair with full capabilities.

resource "pkcs11_key_pair" "full_caps" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    encrypt         = true
    label           = "test-22-full-caps"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    decrypt  = true
    label    = "test-22-full-caps"
  }
}

check "pub_verify" {
  assert {
    condition     = pkcs11_key_pair.full_caps.public_key.verify == true
    error_message = "Public key should have verify"
  }
}

check "pub_encrypt" {
  assert {
    condition     = pkcs11_key_pair.full_caps.public_key.encrypt == true
    error_message = "Public key should have encrypt"
  }
}

check "priv_sign" {
  assert {
    condition     = pkcs11_key_pair.full_caps.private_key.sign == true
    error_message = "Private key should have sign"
  }
}

check "priv_decrypt" {
  assert {
    condition     = pkcs11_key_pair.full_caps.private_key.decrypt == true
    error_message = "Private key should have decrypt"
  }
}
