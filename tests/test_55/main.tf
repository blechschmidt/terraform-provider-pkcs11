# Test 55: Sign with EC key using CKM_ECDSA
resource "pkcs11_key_pair" "ec_key" {
  mechanism = "CKM_EC_KEY_PAIR_GEN"

  public_key = {
    label     = "test-55-ec-pub"
    class     = "CKO_PUBLIC_KEY"
    key_type  = "CKK_EC"
    ec_params = "BggqhkjOPQMBBw==" # P-256 OID
    token     = true
    verify    = true
  }

  private_key = {
    label       = "test-55-ec-priv"
    class       = "CKO_PRIVATE_KEY"
    key_type    = "CKK_EC"
    token       = true
    sign        = true
    sensitive   = true
    extractable = false
  }
}

data "pkcs11_signature" "sig" {
  depends_on = [pkcs11_key_pair.ec_key]
  mechanism  = "CKM_ECDSA"
  key_label  = "test-55-ec-priv"
  data       = base64encode("01234567890123456789012345678901") # 32 bytes for SHA-256 hash
}

check "ec_sign_works" {
  assert {
    condition     = data.pkcs11_signature.sig.signature != ""
    error_message = "EC signing should produce a non-empty signature"
  }
}
