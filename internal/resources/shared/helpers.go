package shared

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/miekg/pkcs11"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
	customtypes "blechschmidt.io/terraform-provider-pkcs11/internal/types"
)

// ObjectAttrSchema builds a map of Terraform schema attributes from the PKCS#11 ObjectAttrs definitions.
func ObjectAttrSchema() map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{}

	for _, def := range pkcs11client.ObjectAttrs {
		switch def.AttrType {
		case pkcs11client.AttrTypeBool:
			a := schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: fmt.Sprintf("PKCS#11 attribute %s.", def.TFKey),
				Sensitive:   def.Sensitive,
			}
			if def.ForceNew || def.Immutable {
				a.PlanModifiers = []planmodifier.Bool{
					BoolRequiresReplace{},
				}
			}
			attrs[def.TFKey] = a

		case pkcs11client.AttrTypeString:
			a := schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: fmt.Sprintf("PKCS#11 attribute %s.", def.TFKey),
				Sensitive:   def.Sensitive,
			}
			if def.ForceNew || def.Immutable {
				a.PlanModifiers = []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				}
			}
			attrs[def.TFKey] = a

		case pkcs11client.AttrTypeBytes:
			a := schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: fmt.Sprintf("PKCS#11 attribute %s (base64-encoded).", def.TFKey),
				Sensitive:   def.Sensitive,
				Validators:  []validator.String{customtypes.Base64Validator{}},
			}
			if def.ForceNew || def.Immutable {
				a.PlanModifiers = []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				}
			}
			attrs[def.TFKey] = a

		case pkcs11client.AttrTypeHex:
			a := schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: fmt.Sprintf("PKCS#11 attribute %s (hex-encoded).", def.TFKey),
				Sensitive:   def.Sensitive,
				Validators:  []validator.String{customtypes.HexValidator{}},
			}
			if def.ForceNew || def.Immutable {
				a.PlanModifiers = []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				}
			}
			attrs[def.TFKey] = a

		case pkcs11client.AttrTypeUlong:
			if def.Pkcs11Enum != nil {
				a := schema.StringAttribute{
					Optional:    true,
					Computed:    true,
					Description: fmt.Sprintf("PKCS#11 attribute %s. Accepts constant name (e.g. %sFOO) or numeric value.", def.TFKey, def.Pkcs11Enum.Prefix),
					Sensitive:   def.Sensitive,
				}
				mods := []planmodifier.String{EnumNormalizer{Enum: def.Pkcs11Enum}}
				if def.ForceNew || def.Immutable {
					mods = append(mods, stringplanmodifier.RequiresReplace())
				}
				a.PlanModifiers = mods
				attrs[def.TFKey] = a
			} else {
				a := schema.Int64Attribute{
					Optional:    true,
					Computed:    true,
					Description: fmt.Sprintf("PKCS#11 attribute %s.", def.TFKey),
					Sensitive:   def.Sensitive,
				}
				if def.ForceNew || def.Immutable {
					a.PlanModifiers = []planmodifier.Int64{
						int64planmodifier.RequiresReplace(),
					}
				}
				attrs[def.TFKey] = a
			}
		}
	}

	return attrs
}

// AttrReader abstracts reading attributes from either a Plan or State.
type AttrReader interface {
	GetAttribute(ctx context.Context, p path.Path, target interface{}) diag.Diagnostics
}

// PlanReader reads attributes from a Terraform plan.
type PlanReader struct {
	Plan tfsdk.Plan
}

func (r PlanReader) GetAttribute(ctx context.Context, p path.Path, target interface{}) diag.Diagnostics {
	return r.Plan.GetAttribute(ctx, p, target)
}

// StateReader reads attributes from Terraform state.
type StateReader struct {
	State tfsdk.State
}

func (r StateReader) GetAttribute(ctx context.Context, p path.Path, target interface{}) diag.Diagnostics {
	return r.State.GetAttribute(ctx, p, target)
}

// AttrsFromPlan reads all non-null PKCS#11 attribute values from a Terraform plan.
func AttrsFromPlan(ctx context.Context, plan tfsdk.Plan) ([]*pkcs11.Attribute, diag.Diagnostics) {
	return readAttrs(ctx, PlanReader{Plan: plan}, path.Root)
}

// AttrsFromState reads all non-null PKCS#11 attribute values from Terraform state.
func AttrsFromState(ctx context.Context, state tfsdk.State) ([]*pkcs11.Attribute, diag.Diagnostics) {
	return readAttrs(ctx, StateReader{State: state}, path.Root)
}

// AttrsFromNestedPlan reads all non-null PKCS#11 attribute values from a nested block in a Terraform plan.
func AttrsFromNestedPlan(ctx context.Context, plan tfsdk.Plan, nestedKey string) ([]*pkcs11.Attribute, diag.Diagnostics) {
	return readAttrs(ctx, PlanReader{Plan: plan}, func(key string) path.Path {
		return path.Root(nestedKey).AtName(key)
	})
}

// AttrsFromNestedState reads all non-null PKCS#11 attribute values from a nested block in Terraform state.
func AttrsFromNestedState(ctx context.Context, state tfsdk.State, nestedKey string) ([]*pkcs11.Attribute, diag.Diagnostics) {
	return readAttrs(ctx, StateReader{State: state}, func(key string) path.Path {
		return path.Root(nestedKey).AtName(key)
	})
}

func readAttrs(ctx context.Context, src AttrReader, pathFn func(string) path.Path) ([]*pkcs11.Attribute, diag.Diagnostics) {
	var diags diag.Diagnostics
	var attrs []*pkcs11.Attribute

	for _, def := range pkcs11client.ObjectAttrs {
		attr, err := readAttribute(ctx, src, def, pathFn)
		if err != nil {
			diags.AddError("Failed to read attribute", err.Error())
			return nil, diags
		}
		if attr != nil {
			attrs = append(attrs, attr)
		}
	}
	return attrs, diags
}

func readAttribute(ctx context.Context, src AttrReader, def pkcs11client.AttrDef, pathFn func(string) path.Path) (*pkcs11.Attribute, error) {
	attrPath := pathFn(def.TFKey)
	switch def.AttrType {
	case pkcs11client.AttrTypeBool:
		var v types.Bool
		src.GetAttribute(ctx, attrPath, &v)
		if v.IsNull() || v.IsUnknown() {
			return nil, nil
		}
		return pkcs11.NewAttribute(def.Type, v.ValueBool()), nil

	case pkcs11client.AttrTypeString:
		var v types.String
		src.GetAttribute(ctx, attrPath, &v)
		if v.IsNull() || v.IsUnknown() {
			return nil, nil
		}
		return pkcs11.NewAttribute(def.Type, v.ValueString()), nil

	case pkcs11client.AttrTypeBytes:
		var v types.String
		src.GetAttribute(ctx, attrPath, &v)
		if v.IsNull() || v.IsUnknown() {
			return nil, nil
		}
		decoded, err := pkcs11client.DecodeBase64(v.ValueString())
		if err != nil {
			return nil, fmt.Errorf("attribute %s: invalid base64: %w", def.TFKey, err)
		}
		return pkcs11.NewAttribute(def.Type, decoded), nil

	case pkcs11client.AttrTypeHex:
		var v types.String
		src.GetAttribute(ctx, attrPath, &v)
		if v.IsNull() || v.IsUnknown() {
			return nil, nil
		}
		decoded, err := pkcs11client.DecodeHex(v.ValueString())
		if err != nil {
			return nil, fmt.Errorf("attribute %s: invalid hex: %w", def.TFKey, err)
		}
		return pkcs11.NewAttribute(def.Type, decoded), nil

	case pkcs11client.AttrTypeUlong:
		if def.Pkcs11Enum != nil {
			var v types.String
			src.GetAttribute(ctx, attrPath, &v)
			if v.IsNull() || v.IsUnknown() {
				return nil, nil
			}
			id, err := def.Pkcs11Enum.Resolve(v.ValueString())
			if err != nil {
				return nil, fmt.Errorf("attribute %s: %w", def.TFKey, err)
			}
			return pkcs11.NewAttribute(def.Type, id), nil
		}
		var v types.Int64
		src.GetAttribute(ctx, attrPath, &v)
		if v.IsNull() || v.IsUnknown() {
			return nil, nil
		}
		return pkcs11.NewAttribute(def.Type, uint(v.ValueInt64())), nil
	}

	return nil, nil
}

// AttrTypesFrom extracts attribute types from an attribute list.
func AttrTypesFrom(attrs []*pkcs11.Attribute) []uint {
	types := make([]uint, len(attrs))
	for i, a := range attrs {
		types[i] = a.Type
	}
	return types
}

// AttrDefByType looks up an attribute definition by PKCS#11 type constant.
func AttrDefByType(t uint) (pkcs11client.AttrDef, bool) {
	for _, def := range pkcs11client.ObjectAttrs {
		if def.Type == t {
			return def, true
		}
	}
	return pkcs11client.AttrDef{}, false
}

// AttributeValuesEqual compares two attribute values for equality.
func AttributeValuesEqual(a, b *pkcs11.Attribute) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(a.Value) != len(b.Value) {
		return false
	}
	for i := range a.Value {
		if a.Value[i] != b.Value[i] {
			return false
		}
	}
	return true
}

// ReadObjectIntoState queries all readable attributes from the token and writes them to state at root level.
// An optional reference reader can be provided to preserve user-provided enum values (e.g. pass PlanReader during Create).
func ReadObjectIntoState(ctx context.Context, client *pkcs11client.Client, handle pkcs11.ObjectHandle, state *tfsdk.State, ref ...AttrReader) diag.Diagnostics {
	var r AttrReader
	if len(ref) > 0 {
		r = ref[0]
	}
	return readObjectIntoStateAt(ctx, client, handle, state, path.Root, r)
}

// ReadObjectIntoNestedState queries all readable attributes from the token and writes them to a nested block in state.
// An optional reference reader can be provided to preserve user-provided enum values (e.g. pass PlanReader during Create).
func ReadObjectIntoNestedState(ctx context.Context, client *pkcs11client.Client, handle pkcs11.ObjectHandle, state *tfsdk.State, nestedKey string, ref ...AttrReader) diag.Diagnostics {
	var r AttrReader
	if len(ref) > 0 {
		r = ref[0]
	}
	return readObjectIntoStateAt(ctx, client, handle, state, func(key string) path.Path {
		return path.Root(nestedKey).AtName(key)
	}, r)
}

func readObjectIntoStateAt(ctx context.Context, client *pkcs11client.Client, handle pkcs11.ObjectHandle, state *tfsdk.State, pathFn func(string) path.Path, ref AttrReader) diag.Diagnostics {
	var diags diag.Diagnostics

	rawAttrs := client.GetAllObjectAttributes(handle)

	for _, def := range pkcs11client.ObjectAttrs {
		val, ok := rawAttrs[def.Type]
		if !ok || val == nil {
			continue
		}

		attrPath := pathFn(def.TFKey)
		switch def.AttrType {
		case pkcs11client.AttrTypeBool:
			diags.Append(state.SetAttribute(ctx, attrPath, pkcs11client.BytesToBool(val))...)
		case pkcs11client.AttrTypeString:
			diags.Append(state.SetAttribute(ctx, attrPath, string(val))...)
		case pkcs11client.AttrTypeBytes:
			diags.Append(state.SetAttribute(ctx, attrPath, pkcs11client.EncodeBase64(val))...)
		case pkcs11client.AttrTypeHex:
			diags.Append(state.SetAttribute(ctx, attrPath, pkcs11client.EncodeHex(val))...)
		case pkcs11client.AttrTypeUlong:
			if def.Pkcs11Enum != nil {
				hsmID := pkcs11client.BytesToUlong(val)
				// Preserve the user's original value if it resolves to the same ID,
				// avoiding unnecessary diffs when using prefix-less names.
				// Check both current state and the reference (plan) if provided.
				for _, src := range []AttrReader{StateReader{State: *state}, ref} {
					if src == nil {
						continue
					}
					var current types.String
					src.GetAttribute(ctx, attrPath, &current)
					if !current.IsNull() && !current.IsUnknown() {
						currentID, err := def.Pkcs11Enum.Resolve(current.ValueString())
						if err == nil && currentID == hsmID {
							diags.Append(state.SetAttribute(ctx, attrPath, current.ValueString())...)
							goto nextAttr
						}
					}
				}
				diags.Append(state.SetAttribute(ctx, attrPath, def.Pkcs11Enum.Format(hsmID))...)
			} else {
				diags.Append(state.SetAttribute(ctx, attrPath, int64(pkcs11client.BytesToUlong(val)))...)
			}
		}
	nextAttr:
	}

	return diags
}

// FindObject locates a PKCS#11 object using label + key_id + class from state.
func FindObject(ctx context.Context, client *pkcs11client.Client, state tfsdk.State) (pkcs11.ObjectHandle, error) {
	var label types.String
	var keyID types.String
	var class types.String

	state.GetAttribute(ctx, path.Root("label"), &label)
	state.GetAttribute(ctx, path.Root("key_id"), &keyID)
	state.GetAttribute(ctx, path.Root("class"), &class)

	classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum

	var template []*pkcs11.Attribute
	if !label.IsNull() && !label.IsUnknown() {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label.ValueString()))
	}
	if !class.IsNull() && !class.IsUnknown() {
		classID, err := classEnum.Resolve(class.ValueString())
		if err != nil {
			return 0, fmt.Errorf("invalid class: %w", err)
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, classID))
	}
	if !keyID.IsNull() && !keyID.IsUnknown() && keyID.ValueString() != "" {
		id, err := pkcs11client.DecodeBase64(keyID.ValueString())
		if err == nil {
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
		}
	}

	if len(template) == 0 {
		return 0, fmt.Errorf("no identifying attributes (label, class, key_id) found in state")
	}

	return client.FindOneObject(template)
}

// FindObjectWithClass locates a PKCS#11 object using label + key_id from state, with an explicit class override.
func FindObjectWithClass(ctx context.Context, client *pkcs11client.Client, state tfsdk.State, classID uint) (pkcs11.ObjectHandle, error) {
	return findObjectWithClassAt(ctx, client, state, classID, path.Root)
}

// FindObjectFromNested locates a PKCS#11 object using label + key_id from a nested block in state, with an explicit class override.
func FindObjectFromNested(ctx context.Context, client *pkcs11client.Client, state tfsdk.State, nestedKey string, classID uint) (pkcs11.ObjectHandle, error) {
	return findObjectWithClassAt(ctx, client, state, classID, func(key string) path.Path {
		return path.Root(nestedKey).AtName(key)
	})
}

func findObjectWithClassAt(ctx context.Context, client *pkcs11client.Client, state tfsdk.State, classID uint, pathFn func(string) path.Path) (pkcs11.ObjectHandle, error) {
	var label types.String
	var keyID types.String

	state.GetAttribute(ctx, pathFn("label"), &label)
	state.GetAttribute(ctx, pathFn("key_id"), &keyID)

	var template []*pkcs11.Attribute
	if !label.IsNull() && !label.IsUnknown() {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label.ValueString()))
	}
	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, classID))
	if !keyID.IsNull() && !keyID.IsUnknown() && keyID.ValueString() != "" {
		id, err := pkcs11client.DecodeBase64(keyID.ValueString())
		if err == nil {
			template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
		}
	}

	return client.FindOneObject(template)
}

// BuildObjectID builds a composite resource ID from label + key_id + class in state.
func BuildObjectID(ctx context.Context, state *tfsdk.State) string {
	var label types.String
	var keyID types.String
	var class types.String

	state.GetAttribute(ctx, path.Root("label"), &label)
	state.GetAttribute(ctx, path.Root("key_id"), &keyID)
	state.GetAttribute(ctx, path.Root("class"), &class)

	classEnum := pkcs11client.AttributeNameToDef["class"].Pkcs11Enum

	var ckaID []byte
	if !keyID.IsNull() && !keyID.IsUnknown() && keyID.ValueString() != "" {
		ckaID, _ = pkcs11client.DecodeBase64(keyID.ValueString())
	}
	labelStr := ""
	if !label.IsNull() && !label.IsUnknown() {
		labelStr = label.ValueString()
	}
	var classVal uint
	if !class.IsNull() && !class.IsUnknown() {
		classVal, _ = classEnum.Resolve(class.ValueString())
	}
	return pkcs11client.FormatObjectID(labelStr, ckaID, classVal)
}

// BuildKeyPairID builds a composite resource ID from label + key_id in a nested block.
func BuildKeyPairID(ctx context.Context, state *tfsdk.State, nestedKey string) string {
	var label types.String
	var keyID types.String

	state.GetAttribute(ctx, path.Root(nestedKey).AtName("label"), &label)
	state.GetAttribute(ctx, path.Root(nestedKey).AtName("key_id"), &keyID)

	var ckaID []byte
	if !keyID.IsNull() && !keyID.IsUnknown() && keyID.ValueString() != "" {
		ckaID, _ = pkcs11client.DecodeBase64(keyID.ValueString())
	}
	labelStr := ""
	if !label.IsNull() && !label.IsUnknown() {
		labelStr = label.ValueString()
	}
	return labelStr + "/" + pkcs11client.EncodeHex(ckaID)
}

// ParseImportID parses an import ID in the format "label/key_id_hex/CKO_CLASS_NAME".
func ParseImportID(id string) (label string, keyID []byte, classID uint, diags diag.Diagnostics) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 {
		diags.AddError("Invalid import ID", "Expected format: label/key_id_hex/CKO_CLASS_NAME")
		return
	}

	label = parts[0]
	keyIDHex := parts[1]
	className := parts[2]

	var ok bool
	classID, ok = pkcs11client.ObjectClassNameToID[className]
	if !ok {
		diags.AddError("Invalid class name", fmt.Sprintf("Unknown object class: %s", className))
		return
	}

	var err error
	keyID, err = pkcs11client.DecodeHex(keyIDHex)
	if err != nil {
		diags.AddError("Invalid key ID", fmt.Sprintf("key_id is not valid hex: %s", err))
		return
	}

	return
}

// BoolRequiresReplace implements RequiresReplace for Bool attributes.
type BoolRequiresReplace struct{}

func (m BoolRequiresReplace) Description(_ context.Context) string {
	return "If the value of this attribute changes, Terraform will destroy and recreate the resource."
}

func (m BoolRequiresReplace) MarkdownDescription(_ context.Context) string {
	return "If the value of this attribute changes, Terraform will destroy and recreate the resource."
}

func (m BoolRequiresReplace) PlanModifyBool(_ context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	if req.StateValue.IsNull() {
		return
	}
	if !req.PlanValue.Equal(req.StateValue) {
		resp.RequiresReplace = true
	}
}

// EnumNormalizer normalizes enum string values to their canonical PKCS#11 constant names during planning.
type EnumNormalizer struct {
	Enum *pkcs11client.Pkcs11Enum
}

func (m EnumNormalizer) Description(_ context.Context) string {
	return "Normalizes the value to the canonical PKCS#11 constant name."
}

func (m EnumNormalizer) MarkdownDescription(_ context.Context) string {
	return "Normalizes the value to the canonical PKCS#11 constant name."
}

func (m EnumNormalizer) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	_, err := m.Enum.Resolve(req.PlanValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid enum value", err.Error())
		return
	}
}

// MechanismNormalizer normalizes mechanism name values to their canonical CKM_ names during planning.
type MechanismNormalizer struct{}

func (m MechanismNormalizer) Description(_ context.Context) string {
	return "Normalizes the value to the canonical PKCS#11 mechanism name."
}

func (m MechanismNormalizer) MarkdownDescription(_ context.Context) string {
	return "Normalizes the value to the canonical PKCS#11 mechanism name."
}

func (m MechanismNormalizer) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	_, err := pkcs11client.MechanismEnum.Resolve(req.PlanValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid mechanism", err.Error())
		return
	}
}
