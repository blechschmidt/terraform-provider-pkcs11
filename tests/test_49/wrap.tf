# Phase 1: Create AES-256 wrapping key, RSA key pair, and wrap the private key
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_GENERIC_SECRET_KEY_GEN"
  label       = "test-49-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_YUBICO_AES256_CCM_WRAP"
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
  mechanism          = "CKM_YUBICO_AES_CCM_WRAP"
  wrapping_key_label = "test-49-wrapping-key"
  key_label          = "test-49-rsa-key"
  key_class          = "CKO_PRIVATE_KEY"
}

output "wrapped_key_material" {
  value     = pkcs11_wrapped_key.wrapped_rsa.wrapped_key_material
  sensitive = true
}
