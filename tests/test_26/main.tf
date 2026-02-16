# Test 26: RSA key pair with encrypt/decrypt only (no sign/verify)
# Validates creating an RSA key pair for encryption only.

resource "pkcs11_key_pair" "encrypt_only" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = false
    encrypt         = true
    label           = "test-26-encrypt-only"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = false
    decrypt  = true
    label    = "test-26-encrypt-only"
  }
}

check "pub_encrypt_enabled" {
  assert {
    condition     = pkcs11_key_pair.encrypt_only.public_key.encrypt == true
    error_message = "Public key should have encrypt capability"
  }
}

check "priv_decrypt_enabled" {
  assert {
    condition     = pkcs11_key_pair.encrypt_only.private_key.decrypt == true
    error_message = "Private key should have decrypt capability"
  }
}
