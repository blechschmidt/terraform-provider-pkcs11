# Wrap an AES key for export using AES Key Wrap (RFC 3394)
resource "pkcs11_symmetric_key" "wrapping_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "my-wrapping-key"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 32
  token       = true
  sensitive   = true
  extractable = false
  wrap        = true
  unwrap      = true
}

resource "pkcs11_symmetric_key" "target_key" {
  mechanism   = "CKM_AES_KEY_GEN"
  label       = "key-to-export"
  class       = "CKO_SECRET_KEY"
  key_type    = "CKK_AES"
  value_len   = 16
  encrypt     = true
  decrypt     = true
  token       = true
  sensitive   = true
  extractable = true
}

resource "pkcs11_wrapped_key" "wrapped" {
  mechanism          = "CKM_AES_KEY_WRAP"
  wrapping_key_label = pkcs11_symmetric_key.wrapping_key.label
  key_label          = pkcs11_symmetric_key.target_key.label
}

output "wrapped_key_material" {
  value     = pkcs11_wrapped_key.wrapped.wrapped_key_material
  sensitive = true
}
