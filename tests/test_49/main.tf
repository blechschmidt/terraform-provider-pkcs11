# Test 49: Unwrap RSA private key (two-phase)
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped_rsa" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-49-wrapping-key"
  wrapped_key_material  = var.wrapped_key_material
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
