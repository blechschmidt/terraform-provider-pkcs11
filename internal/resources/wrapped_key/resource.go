package wrapped_key

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

var _ resource.Resource = &WrappedKeyResource{}

type WrappedKeyResource struct {
	client *pkcs11client.Client
}

func NewResource() resource.Resource {
	return &WrappedKeyResource{}
}

func (r *WrappedKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wrapped_key"
}

func (r *WrappedKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum

	resp.Schema = schema.Schema{
		Description: "Wraps (exports) an existing key from a PKCS#11 token using C_WrapKey. " +
			"The encrypted key material is stored as a computed attribute.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"mechanism": schema.StringAttribute{
				Required:    true,
				Description: "Wrapping mechanism name (e.g., CKM_AES_KEY_WRAP). Accepts name with or without CKM_ prefix, or numeric value.",
				PlanModifiers: []planmodifier.String{
					shared.MechanismNormalizer{},
					stringplanmodifier.RequiresReplace(),
				},
			},
			"wrapping_key_label": schema.StringAttribute{
				Required:    true,
				Description: "Label of the wrapping key on the token.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"wrapping_key_class": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Object class of the wrapping key (default: CKO_SECRET_KEY).",
				PlanModifiers: []planmodifier.String{
					shared.EnumNormalizer{Enum: classEnum},
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_label": schema.StringAttribute{
				Required:    true,
				Description: "Label of the key to wrap.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_class": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Object class of the key to wrap (default: CKO_SECRET_KEY).",
				PlanModifiers: []planmodifier.String{
					shared.EnumNormalizer{Enum: classEnum},
					stringplanmodifier.RequiresReplace(),
				},
			},
			"wrapped_key_material": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The wrapped (encrypted) key material, base64-encoded.",
				Validators:  []validator.String{customtypes.Base64Validator{}},
			},
		},
	}
}

func (r *WrappedKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *WrappedKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	wrappedData, diags := r.wrapKey(ctx, shared.PlanReader{Plan: req.Plan})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Copy all plan values to state
	var mechanism, wrappingKeyLabel, wrappingKeyClass, keyLabel, keyClass types.String
	req.Plan.GetAttribute(ctx, path.Root("mechanism"), &mechanism)
	req.Plan.GetAttribute(ctx, path.Root("wrapping_key_label"), &wrappingKeyLabel)
	req.Plan.GetAttribute(ctx, path.Root("wrapping_key_class"), &wrappingKeyClass)
	req.Plan.GetAttribute(ctx, path.Root("key_label"), &keyLabel)
	req.Plan.GetAttribute(ctx, path.Root("key_class"), &keyClass)

	wkClass := "CKO_SECRET_KEY"
	if !wrappingKeyClass.IsNull() && !wrappingKeyClass.IsUnknown() {
		wkClass = wrappingKeyClass.ValueString()
	}
	kClass := "CKO_SECRET_KEY"
	if !keyClass.IsNull() && !keyClass.IsUnknown() {
		kClass = keyClass.ValueString()
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mechanism"), mechanism.ValueString())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("wrapping_key_label"), wrappingKeyLabel.ValueString())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("wrapping_key_class"), wkClass)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_label"), keyLabel.ValueString())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_class"), kClass)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("wrapped_key_material"), pkcs11client.EncodeBase64(wrappedData))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"),
		fmt.Sprintf("%s/%s", wrappingKeyLabel.ValueString(), keyLabel.ValueString()))...)
}

func (r *WrappedKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Re-wrap to get current material
	wrappedData, diags := r.wrapKey(ctx, shared.StateReader{State: req.State})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("wrapped_key_material"), pkcs11client.EncodeBase64(wrappedData))...)
}

func (r *WrappedKeyResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All inputs are RequiresReplace, so Update should never be called.
	resp.Diagnostics.AddError("Unexpected update", "All attributes require replacement; update should not be called.")
}

func (r *WrappedKeyResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: wrapping doesn't create objects on the HSM.
}

// wrapKey performs the actual C_WrapKey operation using attributes from a plan or state.
func (r *WrappedKeyResource) wrapKey(ctx context.Context, src shared.AttrReader) ([]byte, diag.Diagnostics) {
	var diags diag.Diagnostics

	var mechanismName, wrappingKeyLabel, wrappingKeyClass, keyLabel, keyClass types.String
	src.GetAttribute(ctx, path.Root("mechanism"), &mechanismName)
	src.GetAttribute(ctx, path.Root("wrapping_key_label"), &wrappingKeyLabel)
	src.GetAttribute(ctx, path.Root("wrapping_key_class"), &wrappingKeyClass)
	src.GetAttribute(ctx, path.Root("key_label"), &keyLabel)
	src.GetAttribute(ctx, path.Root("key_class"), &keyClass)

	mechanismID, err := pkcs11client.MechanismEnum.Resolve(mechanismName.ValueString())
	if err != nil {
		diags.AddError("Invalid mechanism", err.Error())
		return nil, diags
	}

	wkClassID := uint(pkcs11.CKO_SECRET_KEY)
	if !wrappingKeyClass.IsNull() && !wrappingKeyClass.IsUnknown() && wrappingKeyClass.ValueString() != "" {
		classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum
		wkClassID, err = classEnum.Resolve(wrappingKeyClass.ValueString())
		if err != nil {
			diags.AddError("Invalid wrapping_key_class", err.Error())
			return nil, diags
		}
	}

	kClassID := uint(pkcs11.CKO_SECRET_KEY)
	if !keyClass.IsNull() && !keyClass.IsUnknown() && keyClass.ValueString() != "" {
		classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum
		kClassID, err = classEnum.Resolve(keyClass.ValueString())
		if err != nil {
			diags.AddError("Invalid key_class", err.Error())
			return nil, diags
		}
	}

	wrappingKeyHandle, err := r.client.FindObjectByLabelAndClass(wrappingKeyLabel.ValueString(), wkClassID)
	if err != nil {
		diags.AddError("Failed to find wrapping key", err.Error())
		return nil, diags
	}

	keyHandle, err := r.client.FindObjectByLabelAndClass(keyLabel.ValueString(), kClassID)
	if err != nil {
		diags.AddError("Failed to find key to wrap", err.Error())
		return nil, diags
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismID, nil)}
	wrappedData, err := r.client.WrapKey(mechanism, wrappingKeyHandle, keyHandle)
	if err != nil {
		diags.AddError("Failed to wrap key", err.Error())
		return nil, diags
	}

	return wrappedData, diags
}
