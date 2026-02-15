package pkcs11client

import (
	"github.com/miekg/pkcs11"
)

// GenerateKeyPair generates a key pair using an arbitrary mechanism and attribute templates.
func (c *Client) GenerateKeyPair(mechanism []*pkcs11.Mechanism, pubAttrs, privAttrs []*pkcs11.Attribute) (pub, priv pkcs11.ObjectHandle, err error) {
	err = c.withSession(func(sh pkcs11.SessionHandle) error {
		var genErr error
		pub, priv, genErr = c.ctx.GenerateKeyPair(sh, mechanism, pubAttrs, privAttrs)
		return wrapError("GenerateKeyPair", genErr)
	})
	return
}

// GenerateSymmetricKey generates a symmetric key (AES, DES3, Generic Secret) on the token.
func (c *Client) GenerateSymmetricKey(mechanism []*pkcs11.Mechanism, attrs []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	var handle pkcs11.ObjectHandle
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		var genErr error
		handle, genErr = c.ctx.GenerateKey(sh, mechanism, attrs)
		return wrapError("GenerateKey", genErr)
	})
	return handle, err
}
