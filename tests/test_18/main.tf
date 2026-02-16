# Test 18: Multiple data objects with different labels
# Validates creating data objects with unique labels and reading them back.

resource "pkcs11_object" "alpha" {
  class = "CKO_DATA"
  label = "test-18-alpha"
  value = base64encode("alpha content")
  token = true
}

resource "pkcs11_object" "beta" {
  class = "CKO_DATA"
  label = "test-18-beta"
  value = base64encode("beta content")
  token = true
}

data "pkcs11_object" "find_alpha" {
  depends_on = [pkcs11_object.alpha]
  label      = "test-18-alpha"
  class      = "CKO_DATA"
}

check "alpha_found" {
  assert {
    condition     = data.pkcs11_object.find_alpha.label == "test-18-alpha"
    error_message = "Should find alpha object"
  }
}

check "beta_label" {
  assert {
    condition     = pkcs11_object.beta.label == "test-18-beta"
    error_message = "Beta object label should match"
  }
}
