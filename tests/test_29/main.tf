# Test 29: Data source lookup of an RSA public key
# Validates looking up a public key via the object data source.

resource "pkcs11_key_pair" "for_lookup" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    label           = "test-29-pub-lookup"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    label    = "test-29-pub-lookup"
  }
}

data "pkcs11_object" "pub_key" {
  depends_on = [pkcs11_key_pair.for_lookup]
  label      = "test-29-pub-lookup"
  class      = "CKO_PUBLIC_KEY"
}

check "pub_key_found" {
  assert {
    condition     = data.pkcs11_object.pub_key.label == "test-29-pub-lookup"
    error_message = "Should find the public key"
  }
}

check "pub_key_type" {
  assert {
    condition     = data.pkcs11_object.pub_key.key_type == "CKK_RSA"
    error_message = "Public key type should be CKK_RSA"
  }
}
