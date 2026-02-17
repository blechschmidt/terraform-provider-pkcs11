# Test 46: Verify encrypt/decrypt attributes preserved
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-46-wrapping-key"
  wrapped_key_material  = var.wrapped_key_material
}

check "unwrapped_encrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.encrypt == true
    error_message = "Unwrapped key should have encrypt = true"
  }
}

check "unwrapped_decrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.decrypt == true
    error_message = "Unwrapped key should have decrypt = true"
  }
}

check "unwrapped_sensitive" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.sensitive == true
    error_message = "Unwrapped key should have sensitive = true"
  }
}
