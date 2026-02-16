# Test 16: Symmetric key read-back verification
# Validates that key attributes can be read back correctly after creation.

resource "pkcs11_symmetric_key" "readback" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "test-16-readback"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = false
}

check "label_matches" {
  assert {
    condition     = pkcs11_symmetric_key.readback.label == "test-16-readback"
    error_message = "Label should match"
  }
}

check "class_matches" {
  assert {
    condition     = pkcs11_symmetric_key.readback.class == "CKO_SECRET_KEY"
    error_message = "Class should be CKO_SECRET_KEY"
  }
}

check "sensitive_set" {
  assert {
    condition     = pkcs11_symmetric_key.readback.sensitive == true
    error_message = "Sensitive should be true"
  }
}

check "not_extractable" {
  assert {
    condition     = pkcs11_symmetric_key.readback.extractable == false
    error_message = "Extractable should be false"
  }
}
