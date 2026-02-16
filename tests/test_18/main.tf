# Test 18: Data object with application attribute
# Validates creating a data object with application metadata.

resource "pkcs11_object" "with_app" {
  class       = "CKO_DATA"
  label       = "test-18-with-app"
  application = "test-suite"
  value       = base64encode("app data")
  token       = true
}

check "application_set" {
  assert {
    condition     = pkcs11_object.with_app.application == "test-suite"
    error_message = "Application attribute should be set"
  }
}
