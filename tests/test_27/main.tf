# Test 27: Combined resources — data object, symmetric key, and key pair
# Validates that multiple resource types can coexist in one configuration.

resource "pkcs11_object" "data_obj" {
  class = "CKO_DATA"
  label = "test-27-data"
  value = base64encode("combined test")
  token = true
}

resource "pkcs11_symmetric_key" "sym_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-27-aes"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

resource "pkcs11_key_pair" "kp" {
  mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN"

  public_key = {
    key_type        = "CKK_RSA"
    class           = "CKO_PUBLIC_KEY"
    token           = true
    verify          = true
    label           = "test-27-rsa"
    modulus_bits    = 2048
    public_exponent = "010001"
  }

  private_key = {
    key_type = "CKK_RSA"
    class    = "CKO_PRIVATE_KEY"
    token    = true
    sign     = true
    label    = "test-27-rsa"
  }
}

check "all_resources_created" {
  assert {
    condition     = pkcs11_object.data_obj.label == "test-27-data" && pkcs11_symmetric_key.sym_key.label == "test-27-aes" && pkcs11_key_pair.kp.public_key.label == "test-27-rsa"
    error_message = "All three resource types should be created"
  }
}
