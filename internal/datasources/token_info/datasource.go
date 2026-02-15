package token_info

import (
	"context"
	"fmt"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &TokenInfoDataSource{}

type TokenInfoDataSource struct {
	client *pkcs11client.Client
}

type TokenInfoModel struct {
	Label              types.String `tfsdk:"label"`
	ManufacturerID     types.String `tfsdk:"manufacturer_id"`
	Model              types.String `tfsdk:"model"`
	SerialNumber       types.String `tfsdk:"serial_number"`
	MaxSessionCount    types.Int64  `tfsdk:"max_session_count"`
	SessionCount       types.Int64  `tfsdk:"session_count"`
	MaxRwSessionCount  types.Int64  `tfsdk:"max_rw_session_count"`
	RwSessionCount     types.Int64  `tfsdk:"rw_session_count"`
	MaxPinLen          types.Int64  `tfsdk:"max_pin_len"`
	MinPinLen          types.Int64  `tfsdk:"min_pin_len"`
	TotalPublicMemory  types.Int64  `tfsdk:"total_public_memory"`
	FreePublicMemory   types.Int64  `tfsdk:"free_public_memory"`
	TotalPrivateMemory types.Int64  `tfsdk:"total_private_memory"`
	FreePrivateMemory  types.Int64  `tfsdk:"free_private_memory"`
	HardwareVersion    types.String `tfsdk:"hardware_version"`
	FirmwareVersion    types.String `tfsdk:"firmware_version"`
}

func NewDataSource() datasource.DataSource {
	return &TokenInfoDataSource{}
}

func (d *TokenInfoDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_token_info"
}

func (d *TokenInfoDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads token information from the configured PKCS#11 slot.",
		Attributes: map[string]schema.Attribute{
			"label":                schema.StringAttribute{Computed: true},
			"manufacturer_id":      schema.StringAttribute{Computed: true},
			"model":                schema.StringAttribute{Computed: true},
			"serial_number":        schema.StringAttribute{Computed: true},
			"max_session_count":    schema.Int64Attribute{Computed: true},
			"session_count":        schema.Int64Attribute{Computed: true},
			"max_rw_session_count": schema.Int64Attribute{Computed: true},
			"rw_session_count":     schema.Int64Attribute{Computed: true},
			"max_pin_len":          schema.Int64Attribute{Computed: true},
			"min_pin_len":          schema.Int64Attribute{Computed: true},
			"total_public_memory":  schema.Int64Attribute{Computed: true},
			"free_public_memory":   schema.Int64Attribute{Computed: true},
			"total_private_memory": schema.Int64Attribute{Computed: true},
			"free_private_memory":  schema.Int64Attribute{Computed: true},
			"hardware_version":     schema.StringAttribute{Computed: true},
			"firmware_version":     schema.StringAttribute{Computed: true},
		},
	}
}

func (d *TokenInfoDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*pkcs11client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *pkcs11client.Client, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *TokenInfoDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	info, err := d.client.GetTokenInfo()
	if err != nil {
		resp.Diagnostics.AddError("Failed to get token info", err.Error())
		return
	}

	state := TokenInfoModel{
		Label:              types.StringValue(info.Label),
		ManufacturerID:     types.StringValue(info.ManufacturerID),
		Model:              types.StringValue(info.Model),
		SerialNumber:       types.StringValue(info.SerialNumber),
		MaxSessionCount:    types.Int64Value(int64(info.MaxSessionCount)),
		SessionCount:       types.Int64Value(int64(info.SessionCount)),
		MaxRwSessionCount:  types.Int64Value(int64(info.MaxRwSessionCount)),
		RwSessionCount:     types.Int64Value(int64(info.RwSessionCount)),
		MaxPinLen:          types.Int64Value(int64(info.MaxPinLen)),
		MinPinLen:          types.Int64Value(int64(info.MinPinLen)),
		TotalPublicMemory:  types.Int64Value(int64(info.TotalPublicMemory)),
		FreePublicMemory:   types.Int64Value(int64(info.FreePublicMemory)),
		TotalPrivateMemory: types.Int64Value(int64(info.TotalPrivateMemory)),
		FreePrivateMemory:  types.Int64Value(int64(info.FreePrivateMemory)),
		HardwareVersion:    types.StringValue(info.HardwareVersion),
		FirmwareVersion:    types.StringValue(info.FirmwareVersion),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
