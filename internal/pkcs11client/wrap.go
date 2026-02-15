package pkcs11client

import (
	"github.com/miekg/pkcs11"
)

// WrapKey wraps a key using the specified wrapping key and mechanism.
func (c *Client) WrapKey(mechanism []*pkcs11.Mechanism, wrappingKey, key pkcs11.ObjectHandle) ([]byte, error) {
	var wrappedKey []byte
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		var wrapErr error
		wrappedKey, wrapErr = c.ctx.WrapKey(sh, mechanism, wrappingKey, key)
		return wrapError("WrapKey", wrapErr)
	})
	return wrappedKey, err
}

// UnwrapKey unwraps a key using the specified unwrapping key, mechanism, and template.
func (c *Client) UnwrapKey(mechanism []*pkcs11.Mechanism, unwrappingKey pkcs11.ObjectHandle, wrappedKey []byte, attrs []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	var handle pkcs11.ObjectHandle
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		var unwrapErr error
		handle, unwrapErr = c.ctx.UnwrapKey(sh, mechanism, unwrappingKey, wrappedKey, attrs)
		return wrapError("UnwrapKey", unwrapErr)
	})
	return handle, err
}
