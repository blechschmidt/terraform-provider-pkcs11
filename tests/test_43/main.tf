# Test 43: Unwrap with explicit unwrapping_key_class
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.
# Here we also set unwrapping_key_class explicitly on the unwrap resource.

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-43-wrapping-key"
  unwrapping_key_class  = "CKO_SECRET_KEY"
  wrapped_key_material  = var.wrapped_key_material
}

check "unwrapping_key_class_preserved" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.unwrapping_key_class == "CKO_SECRET_KEY"
    error_message = "unwrapping_key_class should be preserved as CKO_SECRET_KEY"
  }
}
