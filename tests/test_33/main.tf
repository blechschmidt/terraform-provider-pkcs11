# Test 33: Wrap an RSA private key with CKM_AES_KEY_WRAP_PAD
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-33-wrapping-key"
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
    label           = "test-33-rsa-key"
    modulus_bits    = 2048
    public_exponent = "010001"
  }
  private_key = {
    key_type    = "CKK_RSA"
    class       = "CKO_PRIVATE_KEY"
    sign        = true
    decrypt     = true
    token       = true
    label       = "test-33-rsa-key"
    extractable = true
  }
}

resource "pkcs11_wrapped_key" "wrapped_rsa" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_key_pair.rsa_key]
  mechanism          = "CKM_AES_KEY_WRAP_PAD"
  wrapping_key_label = "test-33-wrapping-key"
  key_label          = "test-33-rsa-key"
  key_class          = "CKO_PRIVATE_KEY"
}

check "rsa_wrap_works" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped_rsa.wrapped_key_material != ""
    error_message = "RSA private key wrapping should produce non-empty material"
  }
}
