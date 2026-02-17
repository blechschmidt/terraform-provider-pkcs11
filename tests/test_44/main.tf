# Test 44: Unwrap using prefix-less mechanism name
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.
# Uses "YUBICO_AES_CCM_WRAP" instead of "CKM_YUBICO_AES_CCM_WRAP"
# and "SECRET_KEY" instead of "CKO_SECRET_KEY".

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-44-wrapping-key"
  unwrapping_key_class  = "SECRET_KEY"
  wrapped_key_material  = var.wrapped_key_material
}

check "unwrapped_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Unwrapped key should be a secret key (class normalizes to CKO_ prefix)"
  }
}
