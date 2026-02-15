package pkcs11client

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// FindObjects searches for objects matching the given template and returns up to maxResults handles.
func (c *Client) FindObjects(template []*pkcs11.Attribute, maxResults int) ([]pkcs11.ObjectHandle, error) {
	var handles []pkcs11.ObjectHandle
	err := c.withSession(func(sh pkcs11.SessionHandle) error {
		if err := c.ctx.FindObjectsInit(sh, template); err != nil {
			return wrapError("FindObjectsInit", err)
		}
		defer c.ctx.FindObjectsFinal(sh)

		for {
			objs, _, err := c.ctx.FindObjects(sh, maxResults)
			if err != nil {
				return wrapError("FindObjects", err)
			}
			if len(objs) == 0 {
				break
			}
			handles = append(handles, objs...)
			if len(handles) >= maxResults {
				handles = handles[:maxResults]
				break
			}
		}
		return nil
	})
	return handles, err
}

// FindOneObject finds exactly one object matching the template.
// Returns ErrObjectNotFound if none match, ErrMultipleObjects if more than one matches.
func (c *Client) FindOneObject(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	handles, err := c.FindObjects(template, 2)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, ErrObjectNotFound
	}
	if len(handles) > 1 {
		return 0, fmt.Errorf("%w: found %d objects", ErrMultipleObjects, len(handles))
	}
	return handles[0], nil
}

// FindObjectByLabelAndClass finds an object by its CKA_LABEL and CKA_CLASS.
func (c *Client) FindObjectByLabelAndClass(label string, class uint) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	return c.FindOneObject(template)
}

// FindObjectByLabelIDClass finds an object by CKA_LABEL, CKA_ID, and CKA_CLASS.
func (c *Client) FindObjectByLabelIDClass(label string, id []byte, class uint) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	return c.FindOneObject(template)
}
