# Test 45: Verify unwrapped key retains original label
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.
# YubiHSM preserves the label in the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-45-wrapping-key"
  wrapped_key_material  = var.wrapped_key_material
}

check "unwrapped_label" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.label == "test-45-original-key"
    error_message = "Unwrapped key should retain the original label 'test-45-original-key'"
  }
}
