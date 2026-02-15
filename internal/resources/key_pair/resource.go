package key_pair

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/miekg/pkcs11"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"blechschmidt.io/terraform-provider-pkcs11/internal/resources/shared"
)

var (
	_ resource.Resource                = &KeyPairResource{}
	_ resource.ResourceWithImportState = &KeyPairResource{}
)

type KeyPairResource struct {
	client *pkcs11client.Client
}

func NewResource() resource.Resource {
	return &KeyPairResource{}
}

func (r *KeyPairResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_pair"
}

func (r *KeyPairResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates an asymmetric key pair on a PKCS#11 token using C_GenerateKeyPair. " +
			"Public and private key attributes are specified separately in the public_key and private_key blocks.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Composite resource identifier.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"mechanism": schema.StringAttribute{
				Required:    true,
				Description: "Key pair generation mechanism name (e.g., CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"public_key": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Attributes for the public key template.",
				Attributes:  shared.ObjectAttrSchema(),
			},
			"private_key": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Attributes for the private key template.",
				Attributes:  shared.ObjectAttrSchema(),
			},
		},
	}
}

func (r *KeyPairResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*pkcs11client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *pkcs11client.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *KeyPairResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var mechanismName string
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("mechanism"), &mechanismName)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mechanismID, ok := pkcs11client.MechanismNameToID[mechanismName]
	if !ok {
		resp.Diagnostics.AddError("Invalid mechanism", fmt.Sprintf("Unknown mechanism: %s", mechanismName))
		return
	}

	pubAttrs, diags := shared.AttrsFromNestedPlan(ctx, req.Plan, "public_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privAttrs, diags := shared.AttrsFromNestedPlan(ctx, req.Plan, "private_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismID, nil)}
	pubHandle, privHandle, err := r.client.GenerateKeyPair(mechanism, pubAttrs, privAttrs)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate key pair", err.Error())
		return
	}

	diags = r.readBothKeysIntoState(ctx, pubHandle, privHandle, &resp.State, shared.AttrTypesFrom(pubAttrs), shared.AttrTypesFrom(privAttrs))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mechanism"), mechanismName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildKeyPairID(ctx, &resp.State, "public_key"))...)
}

func (r *KeyPairResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	pubHandle, privHandle, err := r.findBothKeys(ctx, req.State)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	pubStateAttrs, diags := shared.AttrsFromNestedState(ctx, req.State, "public_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privStateAttrs, diags := shared.AttrsFromNestedState(ctx, req.State, "private_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = r.readBothKeysIntoState(ctx, pubHandle, privHandle, &resp.State, shared.AttrTypesFrom(pubStateAttrs), shared.AttrTypesFrom(privStateAttrs))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildKeyPairID(ctx, &resp.State, "public_key"))...)
}

func (r *KeyPairResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	pubHandle, privHandle, err := r.findBothKeys(ctx, req.State)
	if err != nil {
		resp.Diagnostics.AddError("Failed to find key pair for update", err.Error())
		return
	}

	pubPlanAttrs, diags := shared.AttrsFromNestedPlan(ctx, req.Plan, "public_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privPlanAttrs, diags := shared.AttrsFromNestedPlan(ctx, req.Plan, "private_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	pubStateAttrs, diags := shared.AttrsFromNestedState(ctx, req.State, "public_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privStateAttrs, diags := shared.AttrsFromNestedState(ctx, req.State, "private_key")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	pubUpdates := computeUpdates(pubPlanAttrs, pubStateAttrs)
	privUpdates := computeUpdates(privPlanAttrs, privStateAttrs)

	if len(pubUpdates) > 0 {
		if err := r.client.SetAttributeValue(pubHandle, pubUpdates); err != nil {
			resp.Diagnostics.AddError("Failed to update public key", err.Error())
			return
		}
	}
	if len(privUpdates) > 0 {
		if err := r.client.SetAttributeValue(privHandle, privUpdates); err != nil {
			resp.Diagnostics.AddError("Failed to update private key", err.Error())
			return
		}
	}

	diags = r.readBothKeysIntoState(ctx, pubHandle, privHandle, &resp.State, shared.AttrTypesFrom(pubPlanAttrs), shared.AttrTypesFrom(privPlanAttrs))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildKeyPairID(ctx, &resp.State, "public_key"))...)
}

func (r *KeyPairResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	pubHandle, privHandle, err := r.findBothKeys(ctx, req.State)
	if err != nil {
		return // Already gone
	}

	if err := r.client.DestroyObject(pubHandle); err != nil {
		resp.Diagnostics.AddError("Failed to destroy public key", err.Error())
	}
	if err := r.client.DestroyObject(privHandle); err != nil {
		resp.Diagnostics.AddError("Failed to destroy private key", err.Error())
	}
}

func (r *KeyPairResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected format: label/key_id_hex")
		return
	}

	label := parts[0]
	keyIDHex := parts[1]

	keyID, err := pkcs11client.DecodeHex(keyIDHex)
	if err != nil {
		resp.Diagnostics.AddError("Invalid key ID", fmt.Sprintf("key_id is not valid hex: %s", err))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("public_key").AtName("label"), label)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("public_key").AtName("key_id"), pkcs11client.EncodeBase64(keyID))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("private_key").AtName("label"), label)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("private_key").AtName("key_id"), pkcs11client.EncodeBase64(keyID))...)
}

// findBothKeys locates the public and private key objects using label + key_id from nested state blocks.
func (r *KeyPairResource) findBothKeys(ctx context.Context, state tfsdk.State) (pub, priv pkcs11.ObjectHandle, err error) {
	pub, err = shared.FindObjectFromNested(ctx, r.client, state, "public_key", pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return 0, 0, fmt.Errorf("public key: %w", err)
	}
	priv, err = shared.FindObjectFromNested(ctx, r.client, state, "private_key", pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return 0, 0, fmt.Errorf("private key: %w", err)
	}
	return
}

// readBothKeysIntoState reads attributes from both keys into their respective nested state blocks.
func (r *KeyPairResource) readBothKeysIntoState(ctx context.Context, pubHandle, privHandle pkcs11.ObjectHandle, state *tfsdk.State, pubQueryTypes, privQueryTypes []uint) diag.Diagnostics {
	var diags diag.Diagnostics

	diags.Append(shared.ReadObjectIntoNestedState(ctx, r.client, pubHandle, state, "public_key", pubQueryTypes)...)
	if diags.HasError() {
		return diags
	}

	diags.Append(shared.ReadObjectIntoNestedState(ctx, r.client, privHandle, state, "private_key", privQueryTypes)...)
	return diags
}

// computeUpdates computes the set of attributes that have changed between plan and state.
func computeUpdates(planAttrs, stateAttrs []*pkcs11.Attribute) []*pkcs11.Attribute {
	stateByType := make(map[uint]*pkcs11.Attribute, len(stateAttrs))
	for _, a := range stateAttrs {
		stateByType[a.Type] = a
	}

	var updates []*pkcs11.Attribute
	for _, planned := range planAttrs {
		def, ok := shared.AttrDefByType(planned.Type)
		if !ok || def.Immutable || def.Computed {
			continue
		}
		if !shared.AttributeValuesEqual(planned, stateByType[planned.Type]) {
			updates = append(updates, planned)
		}
	}
	return updates
}
