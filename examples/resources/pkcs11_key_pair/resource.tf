# Generate an RSA 2048-bit key pair
resource "pkcs11_key_pair" "rsa_signing" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    encrypt         = true
    label           = "my-rsa-key"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    decrypt  = true
    label    = "my-rsa-key"
  }
}
