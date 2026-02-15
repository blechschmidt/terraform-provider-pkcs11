package mechanisms

import (
	"context"
	"fmt"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &MechanismsDataSource{}

type MechanismsDataSource struct {
	client *pkcs11client.Client
}

type MechanismsModel struct {
	Mechanisms []MechanismModel `tfsdk:"mechanisms"`
}

type MechanismModel struct {
	Type       types.Int64  `tfsdk:"type"`
	Name       types.String `tfsdk:"name"`
	MinKeySize types.Int64  `tfsdk:"min_key_size"`
	MaxKeySize types.Int64  `tfsdk:"max_key_size"`
	Flags      types.Int64  `tfsdk:"flags"`
}

func NewDataSource() datasource.DataSource {
	return &MechanismsDataSource{}
}

func (d *MechanismsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mechanisms"
}

func (d *MechanismsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists mechanisms supported by the PKCS#11 token.",
		Attributes: map[string]schema.Attribute{
			"mechanisms": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type":         schema.Int64Attribute{Computed: true},
						"name":         schema.StringAttribute{Computed: true},
						"min_key_size": schema.Int64Attribute{Computed: true},
						"max_key_size": schema.Int64Attribute{Computed: true},
						"flags":        schema.Int64Attribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *MechanismsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *MechanismsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	mechs, err := d.client.GetMechanismList()
	if err != nil {
		resp.Diagnostics.AddError("Failed to list mechanisms", err.Error())
		return
	}

	state := MechanismsModel{
		Mechanisms: make([]MechanismModel, len(mechs)),
	}
	for i, m := range mechs {
		state.Mechanisms[i] = MechanismModel{
			Type:       types.Int64Value(int64(m.Type)),
			Name:       types.StringValue(m.Name),
			MinKeySize: types.Int64Value(int64(m.MinKeySize)),
			MaxKeySize: types.Int64Value(int64(m.MaxKeySize)),
			Flags:      types.Int64Value(int64(m.Flags)),
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
