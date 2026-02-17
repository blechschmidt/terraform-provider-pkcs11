# Test 49: Wrap and unwrap RSA private key with CKM_AES_KEY_WRAP_PAD
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-49-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_key_pair" "rsa_key" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    encrypt         = true
    label           = "test-49-rsa-key"
    modulus_bits    = 2048
    public_exponent = "010001"
  }
  private_key = {
    key_type    = "CKK_RSA"
    class       = "CKO_PRIVATE_KEY"
    sign        = true
    decrypt     = true
    token       = true
    label       = "test-49-rsa-key"
    extractable = true
  }
}

resource "pkcs11_wrapped_key" "wrapped_rsa" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_key_pair.rsa_key]
  mechanism          = "CKM_AES_KEY_WRAP_PAD"
  wrapping_key_label = "test-49-wrapping-key"
  key_label          = "test-49-rsa-key"
  key_class          = "CKO_PRIVATE_KEY"
}

resource "pkcs11_unwrapped_key" "unwrapped_rsa" {
  depends_on           = [pkcs11_wrapped_key.wrapped_rsa]
  mechanism            = "CKM_AES_KEY_WRAP_PAD"
  unwrapping_key_label = "test-49-wrapping-key"
  wrapped_key_material = pkcs11_wrapped_key.wrapped_rsa.wrapped_key_material

  label     = "test-49-unwrapped-rsa"
  class     = "CKO_PRIVATE_KEY"
  key_type  = "CKK_RSA"
  sign      = true
  decrypt   = true
  token     = true
  sensitive = true
}

check "unwrapped_rsa_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_rsa.class == "CKO_PRIVATE_KEY"
    error_message = "Unwrapped RSA key should have class CKO_PRIVATE_KEY"
  }
}

check "unwrapped_rsa_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_rsa.key_type == "CKK_RSA"
    error_message = "Unwrapped RSA key should have key_type CKK_RSA"
  }
}
