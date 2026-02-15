package provider

import (
	"context"
	"os"
	"strconv"

	"blechschmidt.io/terraform-provider-pkcs11/internal/datasources/constants"
	"blechschmidt.io/terraform-provider-pkcs11/internal/datasources/mechanisms"
	"blechschmidt.io/terraform-provider-pkcs11/internal/datasources/object"
	"blechschmidt.io/terraform-provider-pkcs11/internal/datasources/slots"
	"blechschmidt.io/terraform-provider-pkcs11/internal/datasources/token_info"
	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	key_pair_resource "blechschmidt.io/terraform-provider-pkcs11/internal/resources/key_pair"
	object_resource "blechschmidt.io/terraform-provider-pkcs11/internal/resources/object"
	symmetric_key_resource "blechschmidt.io/terraform-provider-pkcs11/internal/resources/symmetric_key"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &Pkcs11Provider{}

// Pkcs11Provider implements the PKCS#11 Terraform provider.
type Pkcs11Provider struct {
	version string
}

// Pkcs11ProviderModel describes the provider configuration data model.
type Pkcs11ProviderModel struct {
	ModulePath types.String `tfsdk:"module_path"`
	TokenLabel types.String `tfsdk:"token_label"`
	SlotID     types.Int64  `tfsdk:"slot_id"`
	Pin        types.String `tfsdk:"pin"`
	SoPin      types.String `tfsdk:"so_pin"`
	Env        types.Map    `tfsdk:"env"`
}

// New creates a factory function for the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Pkcs11Provider{version: version}
	}
}

func (p *Pkcs11Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pkcs11"
	resp.Version = p.version
}

func (p *Pkcs11Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for managing cryptographic objects on PKCS#11 tokens and HSMs.",
		Attributes: map[string]schema.Attribute{
			"module_path": schema.StringAttribute{
				Description: "Path to the PKCS#11 shared library module. Can also be set via PKCS11_MODULE_PATH env var.",
				Optional:    true,
			},
			"token_label": schema.StringAttribute{
				Description: "Label of the token to use. Mutually exclusive with slot_id. Can also be set via PKCS11_TOKEN_LABEL env var.",
				Optional:    true,
			},
			"slot_id": schema.Int64Attribute{
				Description: "Slot ID to use. Mutually exclusive with token_label. Can also be set via PKCS11_SLOT_ID env var.",
				Optional:    true,
			},
			"pin": schema.StringAttribute{
				Description: "User PIN for the token. Can also be set via PKCS11_PIN env var.",
				Optional:    true,
				Sensitive:   true,
			},
			"so_pin": schema.StringAttribute{
				Description: "Security Officer PIN. Can also be set via PKCS11_SO_PIN env var.",
				Optional:    true,
				Sensitive:   true,
			},
			"env": schema.MapAttribute{
				Description: "Additional environment variables to set for the provider process. This can be used to pass configuration to the PKCS#11 module or for debugging purposes. Values will override any conflicting environment variables set in the shell.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (p *Pkcs11Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config Pkcs11ProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve values from config or environment
	modulePath := stringValueOrEnv(config.ModulePath, "PKCS11_MODULE_PATH")
	tokenLabel := stringValueOrEnv(config.TokenLabel, "PKCS11_TOKEN_LABEL")
	pin := stringValueOrEnv(config.Pin, "PKCS11_PIN")
	soPin := stringValueOrEnv(config.SoPin, "PKCS11_SO_PIN")

	for k, v := range config.Env.Elements() {
		value := v.(types.String).ValueString()
		os.Setenv(k, value)
	}

	if modulePath == "" {
		resp.Diagnostics.AddError("Missing module_path", "module_path must be set in provider config or PKCS11_MODULE_PATH env var")
		return
	}

	var slotID *uint
	if !config.SlotID.IsNull() && !config.SlotID.IsUnknown() {
		v := uint(config.SlotID.ValueInt64())
		slotID = &v
	} else if envVal := os.Getenv("PKCS11_SLOT_ID"); envVal != "" {
		v, err := strconv.ParseUint(envVal, 10, 64)
		if err == nil {
			uv := uint(v)
			slotID = &uv
		}
	}

	if tokenLabel == "" && slotID == nil {
		resp.Diagnostics.AddError("Missing token identifier", "Either token_label or slot_id must be set")
		return
	}

	if tokenLabel != "" && slotID != nil {
		resp.Diagnostics.AddError("Conflicting token identifiers", "Only one of token_label or slot_id may be set")
		return
	}

	cfg := pkcs11client.Config{
		ModulePath: modulePath,
		TokenLabel: tokenLabel,
		SlotID:     slotID,
		Pin:        pin,
		SoPin:      soPin,
		PoolSize:   5,
	}

	client, err := pkcs11client.NewClient(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Failed to initialize PKCS#11 client", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *Pkcs11Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		object_resource.NewResource,
		symmetric_key_resource.NewResource,
		key_pair_resource.NewResource,
	}
}

func (p *Pkcs11Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		slots.NewDataSource,
		token_info.NewDataSource,
		mechanisms.NewDataSource,
		object.NewDataSource,
		constants.NewDataSource,
	}
}

func stringValueOrEnv(val types.String, envKey string) string {
	if !val.IsNull() && !val.IsUnknown() {
		return val.ValueString()
	}
	return os.Getenv(envKey)
}
