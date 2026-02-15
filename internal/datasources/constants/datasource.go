package constants

import (
	"context"
	"strings"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &ConstantsDataSource{}

type ConstantsDataSource struct{}

type Constants struct {
	All map[string]types.Int64 `tfsdk:"all"`
}

func NewDataSource() datasource.DataSource {
	return &ConstantsDataSource{}
}

func (d *ConstantsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_constants"
}

func (d *ConstantsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a mapping of PKCS#11 constant names to their numeric IDs.",
		Attributes: map[string]schema.Attribute{
			"all": schema.MapAttribute{
				Computed:    true,
				ElementType: types.Int64Type,
				Description: "Map of constant name to numeric ID.",
			},
		},
	}
}

func (d *ConstantsDataSource) Configure(_ context.Context, _ datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
}

func (d *ConstantsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	constants := make(map[string]types.Int64, len(pkcs11client.ObjectClassNameToID)+len(pkcs11client.KeyTypeNameToID)+len(pkcs11client.MechanismNameToID))
	for name, id := range pkcs11client.ObjectClassNameToID {
		constants[strings.ToUpper(name)] = types.Int64Value(int64(id))
	}
	for name, id := range pkcs11client.KeyTypeNameToID {
		constants[strings.ToUpper(name)] = types.Int64Value(int64(id))
	}
	for name, id := range pkcs11client.MechanismNameToID {
		constants[strings.ToUpper(name)] = types.Int64Value(int64(id))
	}

	state := Constants{All: constants}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
