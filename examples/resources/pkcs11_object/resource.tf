data "pkcs11_constants" "constants" {}

# Store a data object on the token
resource "pkcs11_object" "my_data" {
  class = data.pkcs11_constants.constants.all["CKO_DATA"]
  label = "my-data-object"
  value = base64encode("hello world")
  token = true
}
