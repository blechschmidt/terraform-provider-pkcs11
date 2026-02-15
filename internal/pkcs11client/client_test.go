package pkcs11client

import (
	"testing"

	"github.com/miekg/pkcs11"
)

func TestNewClientWithContext_ResolvesTokenLabel(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	if client.SlotID() != 0 {
		t.Errorf("expected slot 0, got %d", client.SlotID())
	}
}

func TestNewClientWithContext_ExplicitSlotID(t *testing.T) {
	mock := NewMockContext("test-token")
	slotID := uint(0)
	cfg := Config{
		SlotID:   &slotID,
		Pin:      "1234",
		PoolSize: 2,
	}
	client, err := NewClientWithContext(mock, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer client.Close()

	if client.SlotID() != 0 {
		t.Errorf("expected slot 0, got %d", client.SlotID())
	}
}

func TestNewClientWithContext_TokenNotFound(t *testing.T) {
	mock := NewMockContext("test-token")
	cfg := Config{
		TokenLabel: "nonexistent",
		Pin:        "1234",
		PoolSize:   2,
	}
	_, err := NewClientWithContext(mock, cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

func TestCreateAndFindObject(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "test-data"),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("hello")),
	}

	handle, err := client.CreateObject(attrs)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	// Find by label and class
	found, err := client.FindObjectByLabelAndClass("test-data", pkcs11.CKO_DATA)
	if err != nil {
		t.Fatalf("FindObjectByLabelAndClass failed: %v", err)
	}
	if found != handle {
		t.Errorf("expected handle %v, got %v", handle, found)
	}

	// Get attributes
	result, err := client.GetObjectAttributes(handle, []uint{pkcs11.CKA_VALUE})
	if err != nil {
		t.Fatalf("GetObjectAttributes failed: %v", err)
	}
	if string(result[pkcs11.CKA_VALUE]) != "hello" {
		t.Errorf("expected value 'hello', got %q", string(result[pkcs11.CKA_VALUE]))
	}
}

func TestDestroyObject(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "to-delete"),
	}

	handle, err := client.CreateObject(attrs)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	err = client.DestroyObject(handle)
	if err != nil {
		t.Fatalf("DestroyObject failed: %v", err)
	}

	_, err = client.FindObjectByLabelAndClass("to-delete", pkcs11.CKO_DATA)
	if err != ErrObjectNotFound {
		t.Errorf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestSetAttributeValue(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "mutable"),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("original")),
	}

	handle, err := client.CreateObject(attrs)
	if err != nil {
		t.Fatalf("CreateObject failed: %v", err)
	}

	err = client.SetAttributeValue(handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("updated")),
	})
	if err != nil {
		t.Fatalf("SetAttributeValue failed: %v", err)
	}

	result, err := client.GetObjectAttributes(handle, []uint{pkcs11.CKA_VALUE})
	if err != nil {
		t.Fatalf("GetObjectAttributes failed: %v", err)
	}
	if string(result[pkcs11.CKA_VALUE]) != "updated" {
		t.Errorf("expected 'updated', got %q", string(result[pkcs11.CKA_VALUE]))
	}
}

func TestGetSlotList(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	slots, err := client.GetSlotList(true)
	if err != nil {
		t.Fatalf("GetSlotList failed: %v", err)
	}
	if len(slots) != 1 {
		t.Errorf("expected 1 slot, got %d", len(slots))
	}
	if !slots[0].TokenPresent {
		t.Error("expected token present")
	}
}

func TestGetTokenInfo(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	info, err := client.GetTokenInfo()
	if err != nil {
		t.Fatalf("GetTokenInfo failed: %v", err)
	}
	if info.Label != "test-token" {
		t.Errorf("expected label 'test-token', got %q", info.Label)
	}
}

func TestFindOneObject_NotFound(t *testing.T) {
	client, _ := newTestClient("test-token")
	defer client.Close()

	_, err := client.FindOneObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "nonexistent"),
	})
	if err != ErrObjectNotFound {
		t.Errorf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestAttributeConversions(t *testing.T) {
	// Bool conversions
	if !BytesToBool(BoolToBytes(true)) {
		t.Error("expected true")
	}
	if BytesToBool(BoolToBytes(false)) {
		t.Error("expected false")
	}

	// Ulong conversions
	if BytesToUlong(UlongToBytes(42)) != 42 {
		t.Error("ulong round-trip failed")
	}

	// Base64 round-trip
	data := []byte("hello world")
	encoded := EncodeBase64(data)
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Error("base64 round-trip failed")
	}

	// Hex round-trip
	hexStr := EncodeHex([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	hexBytes, err := DecodeHex(hexStr)
	if err != nil {
		t.Fatalf("DecodeHex failed: %v", err)
	}
	if len(hexBytes) != 4 || hexBytes[0] != 0xDE {
		t.Error("hex round-trip failed")
	}
}
