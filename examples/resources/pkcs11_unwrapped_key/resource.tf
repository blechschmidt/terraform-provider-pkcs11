# Unwrap (import) a previously wrapped AES key
resource "pkcs11_unwrapped_key" "imported" {
  mechanism            = "CKM_AES_KEY_WRAP"
  unwrapping_key_label = "my-wrapping-key"
  wrapped_key_material = var.wrapped_key_material

  # Template attributes for the unwrapped key
  label     = "imported-key"
  class     = "CKO_SECRET_KEY"
  key_type  = "CKK_AES"
  encrypt   = true
  decrypt   = true
  token     = true
  sensitive = true
}
