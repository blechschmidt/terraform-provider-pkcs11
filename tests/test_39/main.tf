# Test 39: Wrap an EC private key with CKM_AES_KEY_WRAP_PAD
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-39-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_key_pair" "ec_key" {
  mechanism = "CKM_EC_KEY_PAIR_GEN"

  public_key = {
    key_type    = "CKK_EC"
    class       = "CKO_PUBLIC_KEY"
    token       = true
    verify      = true
    label       = "test-39-ec-key"
    ec_params   = "BggqhkjOPQMBBw==" # secp256r1 / P-256
  }
  private_key = {
    key_type    = "CKK_EC"
    class       = "CKO_PRIVATE_KEY"
    sign        = true
    token       = true
    label       = "test-39-ec-key"
    extractable = true
  }
}

resource "pkcs11_wrapped_key" "wrapped_ec" {
  depends_on         = [pkcs11_symmetric_key.wrapping_key, pkcs11_key_pair.ec_key]
  mechanism          = "CKM_AES_KEY_WRAP_PAD"
  wrapping_key_label = "test-39-wrapping-key"
  key_label          = "test-39-ec-key"
  key_class          = "CKO_PRIVATE_KEY"
}

check "ec_wrap_works" {
  assert {
    condition     = pkcs11_wrapped_key.wrapped_ec.wrapped_key_material != ""
    error_message = "EC private key wrapping should work"
  }
}
