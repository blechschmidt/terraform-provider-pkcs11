package pkcs11client

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// Sentinel errors for common PKCS#11 conditions.
var (
	ErrObjectNotFound    = errors.New("pkcs11: object not found")
	ErrMultipleObjects   = errors.New("pkcs11: multiple objects match")
	ErrSessionClosed     = errors.New("pkcs11: session closed or invalid")
	ErrTokenNotPresent   = errors.New("pkcs11: token not present")
	ErrSlotNotFound      = errors.New("pkcs11: slot not found")
	ErrMechanismInvalid  = errors.New("pkcs11: mechanism invalid")
	ErrAttributeReadOnly = errors.New("pkcs11: attribute read only")
	ErrPinIncorrect      = errors.New("pkcs11: pin incorrect")
)

// Pkcs11Error wraps a PKCS#11 return value with context.
type Pkcs11Error struct {
	Operation string
	Code      pkcs11.Error
}

func (e *Pkcs11Error) Error() string {
	return fmt.Sprintf("pkcs11 %s failed: %s (0x%08X)", e.Operation, e.Code, uint(e.Code))
}

func (e *Pkcs11Error) Unwrap() error {
	return e.Code
}

// wrapError converts a pkcs11 error into a contextual Pkcs11Error.
// If err is nil, returns nil. If err is not a pkcs11.Error, returns it unchanged.
func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var p11err pkcs11.Error
	if errors.As(err, &p11err) {
		return &Pkcs11Error{Operation: operation, Code: p11err}
	}
	return fmt.Errorf("pkcs11 %s: %w", operation, err)
}

// isSessionError returns true if the error indicates a session that needs re-establishment.
func isSessionError(err error) bool {
	var p11err *Pkcs11Error
	if !errors.As(err, &p11err) {
		return false
	}
	switch p11err.Code {
	case pkcs11.CKR_SESSION_HANDLE_INVALID,
		pkcs11.CKR_SESSION_CLOSED,
		pkcs11.CKR_TOKEN_NOT_PRESENT,
		pkcs11.CKR_DEVICE_REMOVED,
		pkcs11.CKR_USER_NOT_LOGGED_IN:
		return true
	}
	return false
}
