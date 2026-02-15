data "pkcs11_constants" "constants" {}

# Generate an RSA 2048-bit key pair
resource "pkcs11_key_pair" "rsa_signing" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = data.pkcs11_constants.constants.all["CKK_RSA"]
    class           = data.pkcs11_constants.constants.all["CKO_PUBLIC_KEY"]
    token           = true
    verify          = true
    encrypt         = true
    label           = "my-rsa-key"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = data.pkcs11_constants.constants.all["CKK_RSA"]
    class    = data.pkcs11_constants.constants.all["CKO_PRIVATE_KEY"]
    token    = true
    sign     = true
    decrypt  = true
    label    = "my-rsa-key"
  }
}
