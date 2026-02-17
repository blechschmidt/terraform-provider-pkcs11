package pkcs11client

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// Pkcs11Context abstracts the miekg/pkcs11.Ctx methods used by the client.
// This interface enables mock-based unit testing without a real PKCS#11 module.
type Pkcs11Context interface {
	Initialize(...pkcs11.InitializeOption) error
	Finalize() error
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error)
	GetMechanismInfo(slotID uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error)
	OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error)
	CloseSession(sh pkcs11.SessionHandle) error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, temp []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, temp []*pkcs11.Attribute) error
	GenerateKeyPair(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, public, private []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	GenerateKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	WrapKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, wrappingKey, key pkcs11.ObjectHandle) ([]byte, error)
	UnwrapKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, unwrappingKey pkcs11.ObjectHandle, wrappedKey []byte, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DeriveKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, baseKey pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
}

// Config holds configuration for creating a Client.
type Config struct {
	ModulePath        string
	TokenLabel        string
	SerialNumber      string
	TokenManufacturer string
	TokenModel        string
	SlotID            *uint
	Pin               string
	SoPin             string
	PoolSize          int
}

// HasTokenFilters returns true if any token-based filter is set in the config.
func HasTokenFilters(cfg Config) bool {
	return cfg.TokenLabel != "" || cfg.SerialNumber != "" ||
		cfg.TokenManufacturer != "" || cfg.TokenModel != ""
}

// Client manages a connection to a PKCS#11 module.
type Client struct {
	ctx    Pkcs11Context
	config Config
	slotID uint
	pool   *SessionPool
	mu     sync.Mutex
}

// NewClient creates a Client from a real pkcs11.Ctx loaded from the module path.
func NewClient(cfg Config) (*Client, error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %q", cfg.ModulePath)
	}
	return NewClientWithContext(ctx, cfg)
}

// NewClientWithContext creates a Client using a provided Pkcs11Context (useful for testing).
func NewClientWithContext(ctx Pkcs11Context, cfg Config) (*Client, error) {
	if err := ctx.Initialize(); err != nil {
		return nil, wrapError("Initialize", err)
	}

	slotID, err := resolveSlot(ctx, cfg)
	if err != nil {
		ctx.Finalize()
		return nil, err
	}

	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 5
	}

	c := &Client{
		ctx:    ctx,
		config: cfg,
		slotID: slotID,
		pool:   NewSessionPool(ctx, slotID, cfg.Pin, poolSize),
	}

	// Ensure sessions are closed when the client is garbage collected.
	// The Terraform Plugin Framework does not call a provider shutdown hook,
	// so this finalizer ensures C_CloseSession and C_Finalize are called.
	runtime.SetFinalizer(c, func(c *Client) {
		c.Close()
	})

	return c, nil
}

// Close releases all sessions and finalizes the PKCS#11 module.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pool.CloseAll()
	return wrapError("Finalize", c.ctx.Finalize())
}

// SlotID returns the resolved slot ID.
func (c *Client) SlotID() uint {
	return c.slotID
}

// Context returns the underlying Pkcs11Context.
func (c *Client) Context() Pkcs11Context {
	return c.ctx
}

// withSession executes fn with a session from the pool. If a session error occurs,
// the session is discarded and the operation retried once with a fresh session.
func (c *Client) withSession(fn func(sh pkcs11.SessionHandle) error) error {
	sh, err := c.pool.Get()
	if err != nil {
		return err
	}

	err = fn(sh)
	if err != nil && isSessionError(err) {
		// Discard the bad session and retry once
		c.ctx.CloseSession(sh)
		sh, err = c.pool.Get()
		if err != nil {
			return err
		}
		err = fn(sh)
	}

	if err != nil {
		// Still return session to pool even on non-session errors
		c.pool.Put(sh)
		return err
	}

	c.pool.Put(sh)
	return nil
}

// tokenMatches checks whether a token's info matches all non-empty filter fields in the config.
func tokenMatches(info pkcs11.TokenInfo, cfg Config) bool {
	if cfg.TokenLabel != "" && info.Label != cfg.TokenLabel {
		return false
	}
	if cfg.SerialNumber != "" && info.SerialNumber != cfg.SerialNumber {
		return false
	}
	if cfg.TokenManufacturer != "" && info.ManufacturerID != cfg.TokenManufacturer {
		return false
	}
	if cfg.TokenModel != "" && info.Model != cfg.TokenModel {
		return false
	}
	return true
}

// resolveSlot finds the slot ID from config (either explicit or by token filters).
func resolveSlot(ctx Pkcs11Context, cfg Config) (uint, error) {
	if cfg.SlotID != nil {
		return *cfg.SlotID, nil
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, wrapError("GetSlotList", err)
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if tokenMatches(info, cfg) {
			return slot, nil
		}
	}

	// Build descriptive error with specified filters
	var filters []string
	if cfg.TokenLabel != "" {
		filters = append(filters, fmt.Sprintf("label=%q", cfg.TokenLabel))
	}
	if cfg.SerialNumber != "" {
		filters = append(filters, fmt.Sprintf("serial_number=%q", cfg.SerialNumber))
	}
	if cfg.TokenManufacturer != "" {
		filters = append(filters, fmt.Sprintf("manufacturer=%q", cfg.TokenManufacturer))
	}
	if cfg.TokenModel != "" {
		filters = append(filters, fmt.Sprintf("model=%q", cfg.TokenModel))
	}
	return 0, fmt.Errorf("%w: no token matching %s", ErrSlotNotFound, strings.Join(filters, ", "))
}
