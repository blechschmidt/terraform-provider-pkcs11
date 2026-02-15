package pkcs11client

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// SessionPool manages a pool of PKCS#11 sessions using a buffered channel.
type SessionPool struct {
	ctx    Pkcs11Context
	slotID uint
	pin    string
	pool   chan pkcs11.SessionHandle
	size   int
}

// NewSessionPool creates a new session pool. Sessions are opened lazily on Get().
func NewSessionPool(ctx Pkcs11Context, slotID uint, pin string, size int) *SessionPool {
	return &SessionPool{
		ctx:    ctx,
		slotID: slotID,
		pin:    pin,
		pool:   make(chan pkcs11.SessionHandle, size),
		size:   size,
	}
}

// Get returns a session from the pool, or opens a new one if the pool is empty.
func (p *SessionPool) Get() (pkcs11.SessionHandle, error) {
	select {
	case sh := <-p.pool:
		return sh, nil
	default:
		return p.openSession()
	}
}

// Put returns a session to the pool. If the pool is full, the session is closed.
func (p *SessionPool) Put(sh pkcs11.SessionHandle) {
	select {
	case p.pool <- sh:
	default:
		p.ctx.CloseSession(sh)
	}
}

// CloseAll drains the pool and closes all sessions.
func (p *SessionPool) CloseAll() {
	for {
		select {
		case sh := <-p.pool:
			p.ctx.CloseSession(sh)
		default:
			return
		}
	}
}

// openSession opens a new R/W session and logs in with the user PIN.
func (p *SessionPool) openSession() (pkcs11.SessionHandle, error) {
	flags := uint(pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION)
	sh, err := p.ctx.OpenSession(p.slotID, flags)
	if err != nil {
		return 0, wrapError("OpenSession", err)
	}

	if p.pin != "" {
		err = p.ctx.Login(sh, pkcs11.CKU_USER, p.pin)
		if err != nil {
			// CKR_USER_ALREADY_LOGGED_IN is OK (another session already logged in)
			p11err, ok := err.(pkcs11.Error)
			if !ok || p11err != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				p.ctx.CloseSession(sh)
				return 0, fmt.Errorf("%w: %v", ErrPinIncorrect, wrapError("Login", err))
			}
		}
	}

	return sh, nil
}
