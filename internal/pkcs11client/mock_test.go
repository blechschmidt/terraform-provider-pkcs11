package pkcs11client

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/miekg/pkcs11"
)

// mockObject represents a stored object in the mock.
type mockObject struct {
	handle pkcs11.ObjectHandle
	attrs  map[uint][]byte
}

// MockContext implements Pkcs11Context for testing.
type MockContext struct {
	mu            sync.Mutex
	initialized   bool
	slots         map[uint]*mockSlot
	sessions      map[pkcs11.SessionHandle]*mockSession
	objects       map[pkcs11.ObjectHandle]*mockObject
	nextSession   atomic.Uint64
	nextObject    atomic.Uint64
	loginRequired bool

	// Error injection
	InitializeErr       error
	OpenSessionErr      error
	LoginErr            error
	CreateObjectErr     error
	GenerateKeyPairErr  error
	GenerateKeyErr      error
	FindObjectsInitErr  error
	GetAttributeErr     error
	SetAttributeErr     error
	DestroyObjectErr    error
	WrapKeyErr          error
	UnwrapKeyErr        error
	DeriveKeyErr        error
}

type mockSlot struct {
	info  pkcs11.SlotInfo
	token *pkcs11.TokenInfo
	mechs []*pkcs11.Mechanism
}

type mockSession struct {
	slotID   uint
	loggedIn bool
	findCtx  []*pkcs11.Attribute // current find template
	findDone bool
}

// NewMockContext creates a MockContext with one slot containing a token.
func NewMockContext(tokenLabel string) *MockContext {
	m := &MockContext{
		slots:    make(map[uint]*mockSlot),
		sessions: make(map[pkcs11.SessionHandle]*mockSession),
		objects:  make(map[pkcs11.ObjectHandle]*mockObject),
	}
	m.slots[0] = &mockSlot{
		info: pkcs11.SlotInfo{
			SlotDescription: "Mock Slot 0",
			ManufacturerID:  "Test",
			Flags:           pkcs11.CKF_TOKEN_PRESENT,
		},
		token: &pkcs11.TokenInfo{
			Label:          tokenLabel,
			ManufacturerID: "Test Manufacturer",
			Model:          "Mock HSM",
			SerialNumber:   "0001",
			MaxPinLen:      32,
			MinPinLen:      4,
		},
		mechs: []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
			pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
			pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
			pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil),
			pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil),
		},
	}
	return m
}

func (m *MockContext) Initialize(opts ...pkcs11.InitializeOption) error {
	if m.InitializeErr != nil {
		return m.InitializeErr
	}
	m.initialized = true
	return nil
}

func (m *MockContext) Finalize() error {
	m.initialized = false
	return nil
}

func (m *MockContext) GetSlotList(tokenPresent bool) ([]uint, error) {
	var result []uint
	for id, slot := range m.slots {
		if !tokenPresent || slot.token != nil {
			result = append(result, id)
		}
	}
	return result, nil
}

func (m *MockContext) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	slot, ok := m.slots[slotID]
	if !ok {
		return pkcs11.SlotInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}
	return slot.info, nil
}

func (m *MockContext) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	slot, ok := m.slots[slotID]
	if !ok || slot.token == nil {
		return pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_TOKEN_NOT_PRESENT)
	}
	return *slot.token, nil
}

func (m *MockContext) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	slot, ok := m.slots[slotID]
	if !ok {
		return nil, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}
	return slot.mechs, nil
}

func (m *MockContext) GetMechanismInfo(slotID uint, mechs []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	return pkcs11.MechanismInfo{
		MinKeySize: 128,
		MaxKeySize: 4096,
		Flags:      pkcs11.CKF_GENERATE_KEY_PAIR | pkcs11.CKF_GENERATE,
	}, nil
}

func (m *MockContext) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	if m.OpenSessionErr != nil {
		return 0, m.OpenSessionErr
	}
	sh := pkcs11.SessionHandle(m.nextSession.Add(1))
	m.mu.Lock()
	m.sessions[sh] = &mockSession{slotID: slotID}
	m.mu.Unlock()
	return sh, nil
}

func (m *MockContext) CloseSession(sh pkcs11.SessionHandle) error {
	m.mu.Lock()
	delete(m.sessions, sh)
	m.mu.Unlock()
	return nil
}

func (m *MockContext) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	if m.LoginErr != nil {
		return m.LoginErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sh]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if sess.loggedIn {
		return pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)
	}
	sess.loggedIn = true
	return nil
}

func (m *MockContext) Logout(sh pkcs11.SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sh]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	sess.loggedIn = false
	return nil
}

func (m *MockContext) CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if m.CreateObjectErr != nil {
		return 0, m.CreateObjectErr
	}
	oh := pkcs11.ObjectHandle(m.nextObject.Add(1))
	attrs := make(map[uint][]byte)
	for _, a := range temp {
		attrs[a.Type] = append([]byte(nil), a.Value...)
	}
	m.mu.Lock()
	m.objects[oh] = &mockObject{handle: oh, attrs: attrs}
	m.mu.Unlock()
	return oh, nil
}

func (m *MockContext) DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	if m.DestroyObjectErr != nil {
		return m.DestroyObjectErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[oh]; !ok {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	delete(m.objects, oh)
	return nil
}

func (m *MockContext) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	if m.FindObjectsInitErr != nil {
		return m.FindObjectsInitErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[sh]
	if sess == nil {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	sess.findCtx = temp
	sess.findDone = false
	return nil
}

func (m *MockContext) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[sh]
	if sess == nil {
		return nil, false, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if sess.findDone {
		return nil, false, nil
	}
	sess.findDone = true

	var result []pkcs11.ObjectHandle
	for _, obj := range m.objects {
		if matchesTemplate(obj, sess.findCtx) {
			result = append(result, obj.handle)
			if len(result) >= max {
				break
			}
		}
	}
	return result, false, nil
}

func (m *MockContext) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[sh]
	if sess != nil {
		sess.findCtx = nil
	}
	return nil
}

func (m *MockContext) GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, temp []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if m.GetAttributeErr != nil {
		return nil, m.GetAttributeErr
	}
	m.mu.Lock()
	obj, ok := m.objects[oh]
	m.mu.Unlock()
	if !ok {
		return nil, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	result := make([]*pkcs11.Attribute, len(temp))
	for i, a := range temp {
		val, exists := obj.attrs[a.Type]
		if exists {
			result[i] = pkcs11.NewAttribute(a.Type, val)
		} else {
			result[i] = pkcs11.NewAttribute(a.Type, nil)
		}
	}
	return result, nil
}

func (m *MockContext) SetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, temp []*pkcs11.Attribute) error {
	if m.SetAttributeErr != nil {
		return m.SetAttributeErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	obj, ok := m.objects[oh]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	for _, a := range temp {
		obj.attrs[a.Type] = append([]byte(nil), a.Value...)
	}
	return nil
}

func (m *MockContext) GenerateKeyPair(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, public, private []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if m.GenerateKeyPairErr != nil {
		return 0, 0, m.GenerateKeyPairErr
	}
	pubOH, err := m.CreateObject(sh, public)
	if err != nil {
		return 0, 0, err
	}
	privOH, err := m.CreateObject(sh, private)
	if err != nil {
		return 0, 0, err
	}
	// Add some computed attributes to the public key
	m.mu.Lock()
	pubObj := m.objects[pubOH]
	if pubObj != nil {
		if _, ok := pubObj.attrs[pkcs11.CKA_MODULUS]; !ok {
			pubObj.attrs[pkcs11.CKA_MODULUS] = []byte{0x00, 0x01} // dummy
		}
	}
	m.mu.Unlock()
	return pubOH, privOH, nil
}

func (m *MockContext) GenerateKey(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if m.GenerateKeyErr != nil {
		return 0, m.GenerateKeyErr
	}
	return m.CreateObject(sh, temp)
}

func (m *MockContext) WrapKey(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, wrappingKey, key pkcs11.ObjectHandle) ([]byte, error) {
	if m.WrapKeyErr != nil {
		return nil, m.WrapKeyErr
	}
	return []byte("mock-wrapped-key"), nil
}

func (m *MockContext) UnwrapKey(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, unwrappingKey pkcs11.ObjectHandle, wrappedKey []byte, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if m.UnwrapKeyErr != nil {
		return 0, m.UnwrapKeyErr
	}
	return m.CreateObject(sh, a)
}

func (m *MockContext) DeriveKey(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, baseKey pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if m.DeriveKeyErr != nil {
		return 0, m.DeriveKeyErr
	}
	return m.CreateObject(sh, a)
}

// matchesTemplate checks if an object matches all attributes in a search template.
func matchesTemplate(obj *mockObject, template []*pkcs11.Attribute) bool {
	for _, t := range template {
		val, ok := obj.attrs[t.Type]
		if !ok {
			return false
		}
		if !bytesEqual(val, t.Value) {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Helper to create a test client with the mock context.
func newTestClient(tokenLabel string) (*Client, *MockContext) {
	mock := NewMockContext(tokenLabel)
	cfg := Config{
		TokenLabel: tokenLabel,
		Pin:        "1234",
		PoolSize:   2,
	}
	client, err := NewClientWithContext(mock, cfg)
	if err != nil {
		panic(fmt.Sprintf("failed to create test client: %v", err))
	}
	return client, mock
}
