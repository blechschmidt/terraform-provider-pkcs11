package unwrapped_key

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/miekg/pkcs11"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	"blechschmidt.io/terraform-provider-pkcs11/internal/resources/shared"
	customtypes "blechschmidt.io/terraform-provider-pkcs11/internal/types"
)

var (
	_ resource.Resource                = &UnwrappedKeyResource{}
	_ resource.ResourceWithImportState = &UnwrappedKeyResource{}
)

type UnwrappedKeyResource struct {
	client *pkcs11client.Client
}

func NewResource() resource.Resource {
	return &UnwrappedKeyResource{}
}

func (r *UnwrappedKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_unwrapped_key"
}

func (r *UnwrappedKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum

	// For unwrapped keys, PKCS#11 object attributes are Optional+Computed.
	// When using standard mechanisms (e.g. CKM_AES_KEY_WRAP), the user provides
	// a template for C_UnwrapKey. When omitted, the HSM determines the values.
	attrs := shared.ComputedObjectAttrSchema()
	attrs["id"] = schema.StringAttribute{
		Computed:    true,
		Description: "Composite resource identifier (label/key_id_hex/CKO_CLASS_NAME).",
		PlanModifiers: []planmodifier.String{
			stringplanmodifier.UseStateForUnknown(),
		},
	}
	attrs["mechanism"] = schema.StringAttribute{
		Required:    true,
		Description: "Unwrapping mechanism name (e.g., CKM_AES_KEY_WRAP). Accepts name with or without CKM_ prefix, or numeric value.",
		PlanModifiers: []planmodifier.String{
			shared.MechanismNormalizer{},
			stringplanmodifier.RequiresReplace(),
		},
	}
	attrs["unwrapping_key_label"] = schema.StringAttribute{
		Required:    true,
		Description: "Label of the unwrapping key on the token.",
		PlanModifiers: []planmodifier.String{
			stringplanmodifier.RequiresReplace(),
		},
	}
	attrs["unwrapping_key_class"] = schema.StringAttribute{
		Optional:    true,
		Computed:    true,
		Description: "Object class of the unwrapping key (default: CKO_SECRET_KEY).",
		PlanModifiers: []planmodifier.String{
			shared.EnumNormalizer{Enum: classEnum},
			stringplanmodifier.RequiresReplace(),
		},
	}
	attrs["wrapped_key_material"] = schema.StringAttribute{
		Required:    true,
		Sensitive:   true,
		Description: "The wrapped (encrypted) key material, base64-encoded.",
		Validators:  []validator.String{customtypes.Base64Validator{}},
		PlanModifiers: []planmodifier.String{
			stringplanmodifier.RequiresReplace(),
		},
	}

	resp.Schema = schema.Schema{
		Description: "Unwraps (imports) encrypted key material onto a PKCS#11 token using C_UnwrapKey. " +
			"For standard mechanisms (e.g. CKM_AES_KEY_WRAP), provide a template with the desired " +
			"attributes (label, class, key_type, etc.). For vendor-specific mechanisms that embed " +
			"attributes in the wrapped blob, the template can be omitted.",
		Attributes: attrs,
	}
}

func (r *UnwrappedKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *UnwrappedKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
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

	// Find the unwrapping key
	unwrappingKeyHandle, diags := r.findUnwrappingKey(ctx, shared.PlanReader{Plan: req.Plan})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Decode wrapped key material
	var wrappedMaterial types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("wrapped_key_material"), &wrappedMaterial)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wrappedBytes, err := pkcs11client.DecodeBase64(wrappedMaterial.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid wrapped_key_material", fmt.Sprintf("not valid base64: %s", err))
		return
	}

	// Build unwrap template from user-provided PKCS#11 attributes.
	// Standard mechanisms (e.g. CKM_AES_KEY_WRAP) require a template;
	// vendor-specific mechanisms may ignore it.
	template, templateDiags := shared.AttrsFromPlan(ctx, req.Plan)
	resp.Diagnostics.Append(templateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismID, nil)}
	handle, err := r.client.UnwrapKey(mechanism, unwrappingKeyHandle, wrappedBytes, template)
	if err != nil {
		resp.Diagnostics.AddError("Failed to unwrap key", err.Error())
		return
	}

	// Read the unwrapped object attributes back into state, using the plan as
	// reference to preserve user-provided enum values.
	diags = shared.ReadObjectIntoState(ctx, r.client, handle, &resp.State, shared.PlanReader{Plan: req.Plan})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set resource-specific attributes
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mechanism"), mechanismName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("wrapped_key_material"), wrappedMaterial.ValueString())...)

	var unwrappingKeyLabel types.String
	req.Plan.GetAttribute(ctx, path.Root("unwrapping_key_label"), &unwrappingKeyLabel)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("unwrapping_key_label"), unwrappingKeyLabel.ValueString())...)

	var unwrappingKeyClass types.String
	req.Plan.GetAttribute(ctx, path.Root("unwrapping_key_class"), &unwrappingKeyClass)
	ukClass := "CKO_SECRET_KEY"
	if !unwrappingKeyClass.IsNull() && !unwrappingKeyClass.IsUnknown() {
		ukClass = unwrappingKeyClass.ValueString()
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("unwrapping_key_class"), ukClass)...)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildObjectID(ctx, &resp.State))...)
}

func (r *UnwrappedKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

func (r *UnwrappedKeyResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All PKCS#11 attributes are Computed-only, so no user-driven updates are possible.
	// All user-specified inputs (mechanism, unwrapping_key_label, wrapped_key_material)
	// have RequiresReplace, so Terraform will never call Update.
	resp.Diagnostics.AddError("Update not supported", "pkcs11_unwrapped_key does not support in-place updates")
}

func (r *UnwrappedKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	handle, err := shared.FindObject(ctx, r.client, req.State)
	if err != nil {
		return // Already gone
	}

	if err := r.client.DestroyObject(handle); err != nil {
		resp.Diagnostics.AddError("Failed to destroy key", err.Error())
	}
}

func (r *UnwrappedKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

// findUnwrappingKey locates the unwrapping key by label and class.
func (r *UnwrappedKeyResource) findUnwrappingKey(ctx context.Context, src shared.AttrReader) (pkcs11.ObjectHandle, diag.Diagnostics) {
	var diags diag.Diagnostics

	var unwrappingKeyLabel, unwrappingKeyClass types.String
	src.GetAttribute(ctx, path.Root("unwrapping_key_label"), &unwrappingKeyLabel)
	src.GetAttribute(ctx, path.Root("unwrapping_key_class"), &unwrappingKeyClass)

	classID := uint(pkcs11.CKO_SECRET_KEY)
	if !unwrappingKeyClass.IsNull() && !unwrappingKeyClass.IsUnknown() && unwrappingKeyClass.ValueString() != "" {
		classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum
		var err error
		classID, err = classEnum.Resolve(unwrappingKeyClass.ValueString())
		if err != nil {
			diags.AddError("Invalid unwrapping_key_class", err.Error())
			return 0, diags
		}
	}

	handle, err := r.client.FindObjectByLabelAndClass(unwrappingKeyLabel.ValueString(), classID)
	if err != nil {
		diags.AddError("Failed to find unwrapping key", err.Error())
		return 0, diags
	}

	return handle, diags
}
