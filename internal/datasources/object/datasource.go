package object

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/miekg/pkcs11"

	"blechschmidt.io/terraform-provider-pkcs11/internal/pkcs11client"
)

var _ datasource.DataSource = &ObjectDataSource{}

type ObjectDataSource struct {
	client *pkcs11client.Client
}

func NewDataSource() datasource.DataSource {
	return &ObjectDataSource{}
}

func (d *ObjectDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_object"
}

func (d *ObjectDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	var attrs = make(map[string]schema.Attribute, len(pkcs11client.ObjectAttrs)+1)
	for _, def := range pkcs11client.ObjectAttrs {
		switch def.AttrType {
		case pkcs11client.AttrTypeString, pkcs11client.AttrTypeBytes, pkcs11client.AttrTypeHex:
			attrs[def.TFKey] = schema.StringAttribute{
				Optional:    true,
				Description: fmt.Sprintf("PKCS#11 attribute CKA_%s", strings.ToUpper(def.TFKey)),
			}
		case pkcs11client.AttrTypeBool:
			attrs[def.TFKey] = schema.BoolAttribute{
				Optional:    true,
				Description: fmt.Sprintf("PKCS#11 attribute CKA_%s", strings.ToUpper(def.TFKey)),
			}
		case pkcs11client.AttrTypeUlong:
			attrs[def.TFKey] = schema.Int64Attribute{
				Optional:    true,
				Description: fmt.Sprintf("PKCS#11 attribute CKA_%s", strings.ToUpper(def.TFKey)),
			}
		}

	}

	attrs["exists"] = schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Description: "If null or set to true, the data source will return an error if no matching object is found. If set to false, the data source will return an empty result instead. The data source will update the field to indicate whether the object exists or not.",
	}

	resp.Schema = schema.Schema{
		Description: "Looks up a PKCS#11 object by attributes (CKA constants without CKA_prefix, lower-cased), returning all readable attributes.",
		Attributes:  attrs,
	}
}

func (d *ObjectDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ObjectDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var must_exist types.Bool

	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("exists"), &must_exist)...)

	template := []*pkcs11.Attribute{}
	for _, def := range pkcs11client.ObjectAttrs {
		var attrVal any
		switch def.AttrType {
		case pkcs11client.AttrTypeBool:
			var boolVal types.Bool
			resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(def.TFKey), &boolVal)...)
			if !boolVal.IsNull() {
				attrVal = boolVal.ValueBool()
			}
		case pkcs11client.AttrTypeString, pkcs11client.AttrTypeBytes, pkcs11client.AttrTypeHex:
			var strVal types.String
			resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(def.TFKey), &strVal)...)
			if !strVal.IsNull() {
				attrVal = strVal.ValueString()
			}
		case pkcs11client.AttrTypeUlong:
			var intVal types.Int64
			resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(def.TFKey), &intVal)...)
			if !intVal.IsNull() {
				attrVal = intVal.ValueInt64()
			}
		}

		if attrVal != nil {
			template = append(template, pkcs11.NewAttribute(def.Type, attrVal))
		}
	}

	handle, err := d.client.FindOneObject(template)
	if err != nil {
		if must_exist.IsNull() || must_exist.ValueBool() {
			resp.Diagnostics.AddError("Object not found", fmt.Sprintf("No object found matching the template: %s", err))
		}
		if !must_exist.IsNull() {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("exists"), false)...)
		}
		return
	}

	if !must_exist.IsNull() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("exists"), true)...)
	}

	rawAttrs := d.client.GetAllObjectAttributes(handle)

	for _, def := range pkcs11client.ObjectAttrs {
		attrName := def.TFKey
		val, ok := rawAttrs[def.Type]
		if !ok || val == nil {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(attrName), val)...)
			continue
		}

		var setVal any

		switch def.AttrType {
		case pkcs11client.AttrTypeBool:
			setVal = pkcs11client.BytesToBool(val)
		case pkcs11client.AttrTypeString:
			setVal = string(val)
		case pkcs11client.AttrTypeBytes:
			setVal = pkcs11client.EncodeBase64(val)
		case pkcs11client.AttrTypeHex:
			setVal = pkcs11client.EncodeHex(val)
		case pkcs11client.AttrTypeUlong:
			setVal = pkcs11client.BytesToUlong(val)
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(attrName), setVal)...)
	}
}
