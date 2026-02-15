package object

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
	_ resource.Resource                = &ObjectResource{}
	_ resource.ResourceWithImportState = &ObjectResource{}
)

type ObjectResource struct {
	client *pkcs11client.Client
}

func NewResource() resource.Resource {
	return &ObjectResource{}
}

func (r *ObjectResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_object"
}

func (r *ObjectResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := shared.ObjectAttrSchema()
	attrs["id"] = schema.StringAttribute{
		Computed:    true,
		Description: "Composite resource identifier (label/key_id_hex/CKO_CLASS_NAME).",
		PlanModifiers: []planmodifier.String{
			stringplanmodifier.UseStateForUnknown(),
		},
	}

	resp.Schema = schema.Schema{
		Description: "Manages a generic PKCS#11 object on a token. All attributes can be specified manually, " +
			"providing full control over object creation for any object type.",
		Attributes: attrs,
	}
}

func (r *ObjectResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ObjectResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	pkcsAttrs, diags := shared.AttrsFromPlan(ctx, req.Plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(pkcsAttrs) == 0 {
		resp.Diagnostics.AddError("No attributes specified", "At least one PKCS#11 attribute must be set.")
		return
	}

	handle, err := r.client.CreateObject(pkcsAttrs)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create object", err.Error())
		return
	}

	diags = shared.ReadObjectIntoState(ctx, r.client, handle, &resp.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildObjectID(ctx, &resp.State))...)
}

func (r *ObjectResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

func (r *ObjectResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	handle, err := shared.FindObject(ctx, r.client, req.State)
	if err != nil {
		resp.Diagnostics.AddError("Failed to find object for update", err.Error())
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
			resp.Diagnostics.AddError("Failed to update object", err.Error())
			return
		}
	}

	diags = shared.ReadObjectIntoState(ctx, r.client, handle, &resp.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), shared.BuildObjectID(ctx, &resp.State))...)
}

func (r *ObjectResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	handle, err := shared.FindObject(ctx, r.client, req.State)
	if err != nil {
		return // Already gone
	}

	if err := r.client.DestroyObject(handle); err != nil {
		resp.Diagnostics.AddError("Failed to destroy object", err.Error())
	}
}

func (r *ObjectResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	label, keyID, classID, diags := shared.ParseImportID(req.ID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("label"), label)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key_id"), pkcs11client.EncodeBase64(keyID))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("class"), int64(classID))...)
}
