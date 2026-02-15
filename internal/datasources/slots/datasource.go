package slots

import (
	"context"
	"fmt"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &SlotsDataSource{}

type SlotsDataSource struct {
	client *pkcs11client.Client
}

type SlotsModel struct {
	TokenPresent types.Bool  `tfsdk:"token_present"`
	Slots        []SlotModel `tfsdk:"slots"`
}

type SlotModel struct {
	SlotID          types.Int64  `tfsdk:"slot_id"`
	SlotDescription types.String `tfsdk:"slot_description"`
	ManufacturerID  types.String `tfsdk:"manufacturer_id"`
	HardwareVersion types.String `tfsdk:"hardware_version"`
	FirmwareVersion types.String `tfsdk:"firmware_version"`
	TokenPresent    types.Bool   `tfsdk:"token_present"`
}

func NewDataSource() datasource.DataSource {
	return &SlotsDataSource{}
}

func (d *SlotsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_slots"
}

func (d *SlotsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists PKCS#11 slots.",
		Attributes: map[string]schema.Attribute{
			"token_present": schema.BoolAttribute{
				Optional:    true,
				Description: "If true, only return slots with a token present. Default: false.",
			},
			"slots": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of slots.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"slot_id": schema.Int64Attribute{
							Computed: true,
						},
						"slot_description": schema.StringAttribute{
							Computed: true,
						},
						"manufacturer_id": schema.StringAttribute{
							Computed: true,
						},
						"hardware_version": schema.StringAttribute{
							Computed: true,
						},
						"firmware_version": schema.StringAttribute{
							Computed: true,
						},
						"token_present": schema.BoolAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *SlotsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *SlotsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config SlotsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tokenPresent := false
	if !config.TokenPresent.IsNull() {
		tokenPresent = config.TokenPresent.ValueBool()
	}

	slots, err := d.client.GetSlotList(tokenPresent)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list slots", err.Error())
		return
	}

	config.Slots = make([]SlotModel, len(slots))
	for i, s := range slots {
		config.Slots[i] = SlotModel{
			SlotID:          types.Int64Value(int64(s.SlotID)),
			SlotDescription: types.StringValue(s.SlotDescription),
			ManufacturerID:  types.StringValue(s.ManufacturerID),
			HardwareVersion: types.StringValue(s.HardwareVersion),
			FirmwareVersion: types.StringValue(s.FirmwareVersion),
			TokenPresent:    types.BoolValue(s.TokenPresent),
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
