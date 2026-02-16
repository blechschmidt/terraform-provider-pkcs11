# Look up an existing object by label
data "pkcs11_object" "my_key" {
  label = "my-signing-key"
  class = "CKO_PUBLIC_KEY"
}

# Look up an object that may or may not exist
data "pkcs11_object" "optional" {
  label  = "my-optional-object"
  exists = false
}

output "object_exists" {
  value = data.pkcs11_object.optional.exists
}
