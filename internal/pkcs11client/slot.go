package pkcs11client

import (
	"github.com/miekg/pkcs11"
)

// SlotInfo contains information about a PKCS#11 slot.
type SlotInfo struct {
	SlotID          uint
	SlotDescription string
	ManufacturerID  string
	HardwareVersion string
	FirmwareVersion string
	Flags           uint
	TokenPresent    bool
}

// TokenInfo contains information about a PKCS#11 token.
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    string
	FirmwareVersion    string
}

// MechanismInfo contains information about a PKCS#11 mechanism.
type MechanismInfo struct {
	Type       uint
	Name       string
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}

// GetSlotList returns a list of available slots.
func (c *Client) GetSlotList(tokenPresent bool) ([]SlotInfo, error) {
	slotIDs, err := c.ctx.GetSlotList(tokenPresent)
	if err != nil {
		return nil, wrapError("GetSlotList", err)
	}

	slots := make([]SlotInfo, 0, len(slotIDs))
	for _, id := range slotIDs {
		info, err := c.ctx.GetSlotInfo(id)
		if err != nil {
			return nil, wrapError("GetSlotInfo", err)
		}
		slots = append(slots, SlotInfo{
			SlotID:          id,
			SlotDescription: info.SlotDescription,
			ManufacturerID:  info.ManufacturerID,
			HardwareVersion: formatVersion(info.HardwareVersion),
			FirmwareVersion: formatVersion(info.FirmwareVersion),
			Flags:           info.Flags,
			TokenPresent:    info.Flags&pkcs11.CKF_TOKEN_PRESENT != 0,
		})
	}
	return slots, nil
}

// GetTokenInfo returns information about the token in the configured slot.
func (c *Client) GetTokenInfo() (*TokenInfo, error) {
	info, err := c.ctx.GetTokenInfo(c.slotID)
	if err != nil {
		return nil, wrapError("GetTokenInfo", err)
	}
	return &TokenInfo{
		Label:              info.Label,
		ManufacturerID:     info.ManufacturerID,
		Model:              info.Model,
		SerialNumber:       info.SerialNumber,
		Flags:              info.Flags,
		MaxSessionCount:    info.MaxSessionCount,
		SessionCount:       info.SessionCount,
		MaxRwSessionCount:  info.MaxRwSessionCount,
		RwSessionCount:     info.RwSessionCount,
		MaxPinLen:          info.MaxPinLen,
		MinPinLen:          info.MinPinLen,
		TotalPublicMemory:  info.TotalPublicMemory,
		FreePublicMemory:   info.FreePublicMemory,
		TotalPrivateMemory: info.TotalPrivateMemory,
		FreePrivateMemory:  info.FreePrivateMemory,
		HardwareVersion:    formatVersion(info.HardwareVersion),
		FirmwareVersion:    formatVersion(info.FirmwareVersion),
	}, nil
}

// GetMechanismList returns the mechanisms supported by the token.
func (c *Client) GetMechanismList() ([]MechanismInfo, error) {
	mechs, err := c.ctx.GetMechanismList(c.slotID)
	if err != nil {
		return nil, wrapError("GetMechanismList", err)
	}

	result := make([]MechanismInfo, 0, len(mechs))
	for _, m := range mechs {
		info, err := c.ctx.GetMechanismInfo(c.slotID, []*pkcs11.Mechanism{m})
		if err != nil {
			continue
		}
		mechType := m.Mechanism
		name := MechanismIDToName[mechType]
		if name == "" {
			name = "UNKNOWN"
		}
		result = append(result, MechanismInfo{
			Type:       mechType,
			Name:       name,
			MinKeySize: info.MinKeySize,
			MaxKeySize: info.MaxKeySize,
			Flags:      info.Flags,
		})
	}
	return result, nil
}

func formatVersion(v pkcs11.Version) string {
	return string(rune('0'+v.Major)) + "." + string(rune('0'+v.Minor))
}
