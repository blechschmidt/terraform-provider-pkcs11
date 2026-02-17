package pkcs11client

import (
	"github.com/miekg/pkcs11"
)

// Encrypt encrypts plaintext using the specified key and mechanism.
func (c *Client) Encrypt(mechanism []*pkcs11.Mechanism, key pkcs11.ObjectHandle, plaintext []byte) ([]byte, error) {
	var ciphertext []byte
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		if err := c.ctx.EncryptInit(sh, mechanism, key); err != nil {
			return wrapError("EncryptInit", err)
		}
		var encErr error
		ciphertext, encErr = c.ctx.Encrypt(sh, plaintext)
		return wrapError("Encrypt", encErr)
	})
	return ciphertext, err
}

// Decrypt decrypts ciphertext using the specified key and mechanism.
func (c *Client) Decrypt(mechanism []*pkcs11.Mechanism, key pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		if err := c.ctx.DecryptInit(sh, mechanism, key); err != nil {
			return wrapError("DecryptInit", err)
		}
		var decErr error
		plaintext, decErr = c.ctx.Decrypt(sh, ciphertext)
		return wrapError("Decrypt", decErr)
	})
	return plaintext, err
}

// Sign signs data using the specified key and mechanism.
func (c *Client) Sign(mechanism []*pkcs11.Mechanism, key pkcs11.ObjectHandle, data []byte) ([]byte, error) {
	var signature []byte
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		if err := c.ctx.SignInit(sh, mechanism, key); err != nil {
			return wrapError("SignInit", err)
		}
		var signErr error
		signature, signErr = c.ctx.Sign(sh, data)
		return wrapError("Sign", signErr)
	})
	return signature, err
}
