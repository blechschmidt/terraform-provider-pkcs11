package decrypt

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/miekg/pkcs11"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
)

var _ datasource.DataSource = &DecryptDataSource{}

type DecryptDataSource struct {
	client *pkcs11client.Client
}

func NewDataSource() datasource.DataSource {
	return &DecryptDataSource{}
}

func (d *DecryptDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decrypt"
}

func (d *DecryptDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts data using a key on the PKCS#11 token via C_DecryptInit + C_Decrypt.",
		Attributes: map[string]schema.Attribute{
			"mechanism": schema.StringAttribute{
				Required:    true,
				Description: "PKCS#11 mechanism name (e.g. CKM_AES_ECB). Accepts CKM_ prefix or without.",
			},
			"key_label": schema.StringAttribute{
				Required:    true,
				Description: "Label of the decryption key on the token.",
			},
			"key_class": schema.StringAttribute{
				Optional:    true,
				Description: "Object class of the key (e.g. CKO_SECRET_KEY, CKO_PRIVATE_KEY). Defaults to CKO_SECRET_KEY.",
			},
			"mechanism_parameter": schema.StringAttribute{
				Optional:    true,
				Description: "Base64-encoded mechanism parameter (e.g. IV for CBC modes).",
			},
			"ciphertext": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Base64-encoded ciphertext to decrypt.",
			},
			"plaintext": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Base64-encoded plaintext result.",
			},
		},
	}
}

func (d *DecryptDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *DecryptDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var mechanism types.String
	var keyLabel types.String
	var keyClass types.String
	var mechParam types.String
	var ciphertext types.String

	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("mechanism"), &mechanism)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("key_label"), &keyLabel)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("key_class"), &keyClass)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("mechanism_parameter"), &mechParam)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("ciphertext"), &ciphertext)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve mechanism
	mechID, err := pkcs11client.MechanismEnum.Resolve(mechanism.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid mechanism", err.Error())
		return
	}

	// Resolve key class
	classID := pkcs11client.ObjectClassNameToID["CKO_SECRET_KEY"]
	if !keyClass.IsNull() && !keyClass.IsUnknown() {
		classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum
		classID, err = classEnum.Resolve(keyClass.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid key_class", err.Error())
			return
		}
	}

	// Find key
	keyHandle, err := d.client.FindObjectByLabelAndClass(keyLabel.ValueString(), classID)
	if err != nil {
		resp.Diagnostics.AddError("Key not found", fmt.Sprintf("Failed to find key with label %q: %s", keyLabel.ValueString(), err))
		return
	}

	// Build mechanism
	var mechParamBytes []byte
	if !mechParam.IsNull() && !mechParam.IsUnknown() {
		mechParamBytes, err = pkcs11client.DecodeBase64(mechParam.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid mechanism_parameter", fmt.Sprintf("Failed to decode base64: %s", err))
			return
		}
	}
	var mech []*pkcs11.Mechanism
	if mechParamBytes != nil {
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(mechID, mechParamBytes)}
	} else {
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(mechID, nil)}
	}

	// Decode ciphertext
	ciphertextBytes, err := pkcs11client.DecodeBase64(ciphertext.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid ciphertext", fmt.Sprintf("Failed to decode base64: %s", err))
		return
	}

	// Decrypt
	plaintext, err := d.client.Decrypt(mech, keyHandle, ciphertextBytes)
	if err != nil {
		resp.Diagnostics.AddError("Decryption failed", err.Error())
		return
	}

	// Set state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mechanism"), mechanism.ValueString())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_label"), keyLabel.ValueString())...)
	if !keyClass.IsNull() && !keyClass.IsUnknown() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_class"), keyClass.ValueString())...)
	}
	if !mechParam.IsNull() && !mechParam.IsUnknown() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mechanism_parameter"), mechParam.ValueString())...)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ciphertext"), ciphertext.ValueString())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("plaintext"), pkcs11client.EncodeBase64(plaintext))...)
}
