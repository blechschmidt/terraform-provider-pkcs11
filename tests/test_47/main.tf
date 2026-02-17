# Test 47: Unwrap with AES-192 wrapping key
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-47-wrapping-key"
  wrapped_key_material  = var.wrapped_key_material
}

check "unwrapped_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Unwrapped key should be a secret key"
  }
}

check "unwrapped_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.key_type == "CKK_AES"
    error_message = "Unwrapped key should be AES"
  }
}
