# Test 42: Verify unwrapped AES-256 key attributes
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-42-wrapping-key"
  wrapped_key_material  = var.wrapped_key_material
}

check "unwrapped_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.key_type == "CKK_AES"
    error_message = "Unwrapped key should be AES"
  }
}

check "unwrapped_value_len" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.value_len == 32
    error_message = "Unwrapped key value_len should be 32 (AES-256)"
  }
}
