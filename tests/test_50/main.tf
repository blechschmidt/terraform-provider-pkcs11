# Test 50: Round-trip verify attributes — wrap AES-128, unwrap, check all attributes
variable "wrapped_key_material" {
  type      = string
  sensitive = true
}

# The wrapping key already exists on the HSM from phase 1.
# All object attributes are computed from the wrapped blob.

resource "pkcs11_unwrapped_key" "unwrapped" {
  mechanism             = "CKM_YUBICO_AES_CCM_WRAP"
  unwrapping_key_label  = "test-50-wrapping-key"
  wrapped_key_material  = var.wrapped_key_material
}

check "roundtrip_class" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.class == "CKO_SECRET_KEY"
    error_message = "Round-trip: class should be CKO_SECRET_KEY"
  }
}

check "roundtrip_key_type" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.key_type == "CKK_AES"
    error_message = "Round-trip: key_type should be CKK_AES"
  }
}

check "roundtrip_value_len" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.value_len == 16
    error_message = "Round-trip: value_len should be 16 (AES-128)"
  }
}

check "roundtrip_encrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.encrypt == true
    error_message = "Round-trip: encrypt should be true"
  }
}

check "roundtrip_decrypt" {
  assert {
    condition     = pkcs11_unwrapped_key.unwrapped.decrypt == true
    error_message = "Round-trip: decrypt should be true"
  }
}
