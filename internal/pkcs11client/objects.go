package pkcs11client

import (
	"github.com/miekg/pkcs11"
)

// CreateObject creates a new object on the token with the given attributes.
func (c *Client) CreateObject(attrs []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	var handle pkcs11.ObjectHandle
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		var err error
		handle, err = c.ctx.CreateObject(sh, attrs)
		return wrapError("CreateObject", err)
	})
	return handle, err
}

// DestroyObject removes an object from the token.
func (c *Client) DestroyObject(handle pkcs11.ObjectHandle) error {
	return c.withSession(func(sh pkcs11.SessionHandle) error {
		return wrapError("DestroyObject", c.ctx.DestroyObject(sh, handle))
	})
}

// GetAttributeValue retrieves attribute values for an object.
func (c *Client) GetAttributeValue(handle pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var result []*pkcs11.Attribute
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		var err error
		result, err = c.ctx.GetAttributeValue(sh, handle, template)
		return wrapError("GetAttributeValue", err)
	})
	return result, err
}

// SetAttributeValue modifies attribute values on an existing object.
func (c *Client) SetAttributeValue(handle pkcs11.ObjectHandle, attrs []*pkcs11.Attribute) error {
	return c.withSession(func(sh pkcs11.SessionHandle) error {
		return wrapError("SetAttributeValue", c.ctx.SetAttributeValue(sh, handle, attrs))
	})
}

// GetObjectAttributes is a convenience function to get multiple attribute values as a map.
func (c *Client) GetObjectAttributes(handle pkcs11.ObjectHandle, attrTypes []uint) (map[uint][]byte, error) {
	template := make([]*pkcs11.Attribute, len(attrTypes))
	for i, t := range attrTypes {
		template[i] = pkcs11.NewAttribute(t, nil)
	}

	result, err := c.GetAttributeValue(handle, template)
	if err != nil {
		return nil, err
	}

	attrs := make(map[uint][]byte, len(result))
	for _, a := range result {
		attrs[a.Type] = a.Value
	}
	return attrs, nil
}

// GetAllObjectAttributes queries every attribute in ObjectAttrs one by one,
// silently skipping any that return errors (e.g. CKR_ATTRIBUTE_TYPE_INVALID).
func (c *Client) GetAllObjectAttributes(handle pkcs11.ObjectHandle) map[uint][]byte {
	attrs := make(map[uint][]byte)
	for _, def := range ObjectAttrs {
		template := []*pkcs11.Attribute{pkcs11.NewAttribute(def.Type, nil)}
		result, err := c.GetAttributeValue(handle, template)
		if err != nil {
			continue
		}
		if len(result) > 0 && result[0].Value != nil {
			attrs[def.Type] = result[0].Value
		}
	}
	return attrs
}
