package types

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Base64Validator validates that a string is valid base64.
type Base64Validator struct{}

func (v Base64Validator) Description(_ context.Context) string {
	return "value must be a valid base64-encoded string"
}

func (v Base64Validator) MarkdownDescription(_ context.Context) string {
	return "value must be a valid base64-encoded string"
}

func (v Base64Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	_, err := base64.StdEncoding.DecodeString(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid base64", fmt.Sprintf("Value is not valid base64: %s", err))
	}
}

// HexValidator validates that a string is valid hex.
type HexValidator struct{}

func (v HexValidator) Description(_ context.Context) string {
	return "value must be a valid hex-encoded string"
}

func (v HexValidator) MarkdownDescription(_ context.Context) string {
	return "value must be a valid hex-encoded string"
}

func (v HexValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	_, err := hex.DecodeString(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid hex", fmt.Sprintf("Value is not valid hex: %s", err))
	}
}
