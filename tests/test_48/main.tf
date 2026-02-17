# Test 48: Unwrap two keys from different wrapped materials (two-phase)
variable "wrapped_a" {
  type      = string
  sensitive = true
}

variable "wrapped_b" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped_a" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-48-wrapping-key"
  wrapped_key_material  = var.wrapped_a
}

resource "pkcs11_unwrapped_key" "unwrapped_b" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-48-wrapping-key"
  wrapped_key_material  = var.wrapped_b
}

check "both_unwrapped" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_a.class == "CKO_SECRET_KEY" && pkcs11_unwrapped_key.unwrapped_b.class == "CKO_SECRET_KEY"
    error_message = "Both keys should be unwrapped as CKO_SECRET_KEY"
  }
}

check "value_len_a" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_a.value_len == 16
    error_message = "Unwrapped key A should have value_len 16"
  }
}

check "value_len_b" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped_b.value_len == 32
    error_message = "Unwrapped key B should have value_len 32"
  }
}
