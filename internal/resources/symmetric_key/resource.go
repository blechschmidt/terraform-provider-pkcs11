package symmetric_key

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/miekg/pkcs11"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"blechschmidt.io/terraform-provider-pkcs11/internal/resources/shared"
)

var (
	_ resource.Resource                = &SymmetricKeyResource{}
	_ resource.ResourceWithImportState = &SymmetricKeyResource{}
)

type SymmetricKeyResource struct {
	client *pkcs11client.Client
}

func NewResource() resource.Resource {
	return &SymmetricKeyResource{}
}

func (r *SymmetricKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_symmetric_key"
}

func (r *SymmetricKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := shared.ObjectAttrSchema()
	attrs["id"] = schema.StringAttribute{
		Computed:    true,
		Description: "Composite resource identifier (label/key_id_hex/CKO_SECRET_KEY).",
		PlanModifiers: []planmodifier.String{
			stringplanmodifier.UseStateForUnknown(),
		},
	}
	attrs["mechanism"] = schema.StringAttribute{
		Required:    true,
		Description: "Key generation mechanism name (e.g., CKM_AES_KEY_GEN, CKM_DES3_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN). Accepts name with or without CKM_ prefix.",
		PlanModifiers: []planmodifier.String{
			shared.MechanismNormalizer{},
			stringplanmodifier.RequiresReplace(),
		},
	}

	resp.Schema = schema.Schema{
		Description: "Generates a symmetric key on a PKCS#11 token using C_GenerateKey. " +
			"All PKCS#11 attributes can be specified to control key properties.",
		Attributes: attrs,
	}
}

func (r *SymmetricKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SymmetricKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var mechanismName string
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("mechanism"), &mechanismName)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mechanismID, err := pkcs11client.MechanismEnum.Resolve(mechanismName)
	if err != nil {
		resp.Diagnostics.AddError("Invalid mechanism", err.Error())
		return
	}

	pkcsAttrs, diags := shared.AttrsFromPlan(ctx, req.Plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismID, nil)}
	handle, err := r.client.GenerateSymmetricKey(mechanism, pkcsAttrs)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate symmetric key", err.Error())
		return
	}

	diags = shared.ReadObjectIntoState(ctx, r.client, handle, &resp.State, shared.PlanReader{Plan: req.Plan})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mechanism"), mechanismName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildObjectID(ctx, &resp.State))...)
}

func (r *SymmetricKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	handle, err := shared.FindObject(ctx, r.client, req.State)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	diags := shared.ReadObjectIntoState(ctx, r.client, handle, &resp.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildObjectID(ctx, &resp.State))...)
}

func (r *SymmetricKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	handle, err := shared.FindObject(ctx, r.client, req.State)
	if err != nil {
		resp.Diagnostics.AddError("Failed to find key for update", err.Error())
		return
	}

	planAttrs, diags := shared.AttrsFromPlan(ctx, req.Plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	stateAttrs, diags := shared.AttrsFromState(ctx, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	if len(updates) > 0 {
		if err := r.client.SetAttributeValue(handle, updates); err != nil {
			resp.Diagnostics.AddError("Failed to update key", err.Error())
			return
		}
	}

	diags = shared.ReadObjectIntoState(ctx, r.client, handle, &resp.State, shared.PlanReader{Plan: req.Plan})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildObjectID(ctx, &resp.State))...)
}

func (r *SymmetricKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	handle, err := shared.FindObject(ctx, r.client, req.State)
	if err != nil {
		return // Already gone
	}

	if err := r.client.DestroyObject(handle); err != nil {
		resp.Diagnostics.AddError("Failed to destroy key", err.Error())
	}
}

func (r *SymmetricKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	label, keyID, classID, diags := shared.ParseImportID(req.ID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("label"), label)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_id"), pkcs11client.EncodeBase64(keyID))...)
	classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("class"), classEnum.Format(classID))...)
}
