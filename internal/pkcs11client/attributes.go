package pkcs11client

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// AttrType represents how an attribute value should be encoded for Terraform.
type AttrType int

const (
	AttrTypeBool   AttrType = iota // CK_BBOOL -> bool
	AttrTypeString                 // UTF8 string -> string
	AttrTypeBytes                  // Raw bytes -> base64 string
	AttrTypeHex                    // Big integer -> hex string
	AttrTypeUlong                  // CK_ULONG -> int64
)

// AttrDef defines the mapping between a PKCS#11 attribute and its Terraform representation.
type AttrDef struct {
	Type      uint     // CKA_* constant
	TFKey     string   // Terraform schema key
	AttrType  AttrType // Value encoding
	Immutable bool     // Requires replacement if changed
	Sensitive bool     // Sensitive in Terraform
	Computed  bool     // Computed by the token
	ForceNew  bool     // Changes force new resource
}

// Object attributes
var ObjectAttrs = []AttrDef{
	{pkcs11.CKA_CLASS, "class", AttrTypeUlong, true, false, true, false},
	{pkcs11.CKA_TOKEN, "token", AttrTypeBool, true, false, false, true},
	{pkcs11.CKA_PRIVATE, "private_flag", AttrTypeBool, true, false, false, true},
	{pkcs11.CKA_LABEL, "label", AttrTypeString, false, false, false, false},
	{pkcs11.CKA_APPLICATION, "application", AttrTypeString, false, false, false, false},
	{pkcs11.CKA_VALUE, "value", AttrTypeBytes, false, true, false, false},
	{pkcs11.CKA_OBJECT_ID, "object_id", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_CERTIFICATE_TYPE, "certificate_type", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_ISSUER, "issuer", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_SERIAL_NUMBER, "serial_number", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_AC_ISSUER, "ac_issuer", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_OWNER, "owner", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_ATTR_TYPES, "attr_types", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_TRUSTED, "trusted", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_CERTIFICATE_CATEGORY, "certificate_category", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN, "java_midp_security_domain", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_URL, "url", AttrTypeString, false, false, false, false},
	{pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "hash_of_subject_public_key", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY, "hash_of_issuer_public_key", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_NAME_HASH_ALGORITHM, "name_hash_algorithm", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_CHECK_VALUE, "check_value", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_KEY_TYPE, "key_type", AttrTypeUlong, true, false, true, false},
	{pkcs11.CKA_SUBJECT, "subject", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_ID, "key_id", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_SENSITIVE, "sensitive", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_ENCRYPT, "encrypt", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_DECRYPT, "decrypt", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_WRAP, "wrap", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_UNWRAP, "unwrap", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_SIGN, "sign", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_SIGN_RECOVER, "sign_recover", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_VERIFY, "verify", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_VERIFY_RECOVER, "verify_recover", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_DERIVE, "derive", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_START_DATE, "start_date", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_END_DATE, "end_date", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_MODULUS, "modulus", AttrTypeHex, false, false, false, false},
	{pkcs11.CKA_MODULUS_BITS, "modulus_bits", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_PUBLIC_EXPONENT, "public_exponent", AttrTypeHex, false, false, false, false},
	{pkcs11.CKA_PRIVATE_EXPONENT, "private_exponent", AttrTypeHex, false, true, false, false},
	{pkcs11.CKA_PRIME_1, "prime_1", AttrTypeHex, false, true, false, false},
	{pkcs11.CKA_PRIME_2, "prime_2", AttrTypeHex, false, true, false, false},
	{pkcs11.CKA_EXPONENT_1, "exponent_1", AttrTypeHex, false, true, false, false},
	{pkcs11.CKA_EXPONENT_2, "exponent_2", AttrTypeHex, false, true, false, false},
	{pkcs11.CKA_COEFFICIENT, "coefficient", AttrTypeHex, false, true, false, false},
	{pkcs11.CKA_PUBLIC_KEY_INFO, "public_key_info", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_PRIME, "prime", AttrTypeHex, false, false, false, false},
	{pkcs11.CKA_SUBPRIME, "subprime", AttrTypeHex, false, false, false, false},
	{pkcs11.CKA_BASE, "base", AttrTypeHex, false, false, false, false},
	{pkcs11.CKA_PRIME_BITS, "prime_bits", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_SUBPRIME_BITS, "subprime_bits", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_VALUE_BITS, "value_bits", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_VALUE_LEN, "value_len", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_EXTRACTABLE, "extractable", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_LOCAL, "local", AttrTypeBool, false, false, true, false},
	{pkcs11.CKA_NEVER_EXTRACTABLE, "never_extractable", AttrTypeBool, false, false, true, false},
	{pkcs11.CKA_ALWAYS_SENSITIVE, "always_sensitive", AttrTypeBool, false, false, true, false},
	{pkcs11.CKA_KEY_GEN_MECHANISM, "key_gen_mechanism", AttrTypeUlong, false, false, true, false},
	{pkcs11.CKA_MODIFIABLE, "modifiable", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_COPYABLE, "copyable", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_DESTROYABLE, "destroyable", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_EC_PARAMS, "ec_params", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_EC_POINT, "ec_point", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_ALWAYS_AUTHENTICATE, "always_authenticate", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_WRAP_WITH_TRUSTED, "wrap_with_trusted", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_OTP_FORMAT, "otp_format", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_LENGTH, "otp_length", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_TIME_INTERVAL, "otp_time_interval", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_USER_FRIENDLY_MODE, "otp_user_friendly_mode", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT, "otp_challenge_requirement", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_TIME_REQUIREMENT, "otp_time_requirement", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_COUNTER_REQUIREMENT, "otp_counter_requirement", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_PIN_REQUIREMENT, "otp_pin_requirement", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_OTP_COUNTER, "otp_counter", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_OTP_TIME, "otp_time", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_OTP_USER_IDENTIFIER, "otp_user_identifier", AttrTypeString, false, false, false, false},
	{pkcs11.CKA_OTP_SERVICE_IDENTIFIER, "otp_service_identifier", AttrTypeString, false, false, false, false},
	{pkcs11.CKA_OTP_SERVICE_LOGO, "otp_service_logo", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_OTP_SERVICE_LOGO_TYPE, "otp_service_logo_type", AttrTypeString, false, false, false, false},
	{pkcs11.CKA_GOSTR3410_PARAMS, "gostr3410_params", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_GOSTR3411_PARAMS, "gostr3411_params", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_GOST28147_PARAMS, "gost28147_params", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_HW_FEATURE_TYPE, "hw_feature_type", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_RESET_ON_INIT, "reset_on_init", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_HAS_RESET, "has_reset", AttrTypeBool, false, false, true, false},
	{pkcs11.CKA_PIXEL_X, "pixel_x", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_PIXEL_Y, "pixel_y", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_RESOLUTION, "resolution", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_CHAR_ROWS, "char_rows", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_CHAR_COLUMNS, "char_columns", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_COLOR, "color", AttrTypeBool, false, false, false, false},
	{pkcs11.CKA_BITS_PER_PIXEL, "bits_per_pixel", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_CHAR_SETS, "char_sets", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_ENCODING_METHODS, "encoding_methods", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_MIME_TYPES, "mime_types", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_MECHANISM_TYPE, "mechanism_type", AttrTypeUlong, false, false, false, false},
	{pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES, "required_cms_attributes", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES, "default_cms_attributes", AttrTypeBytes, false, false, false, false},
	{pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES, "supported_cms_attributes", AttrTypeBytes, false, false, false, false},
}

var AttributeNameToDef map[string]AttrDef

func init() {
	AttributeNameToDef = make(map[string]AttrDef, len(ObjectAttrs))
	for index := range ObjectAttrs {
		AttributeNameToDef[ObjectAttrs[index].TFKey] = ObjectAttrs[index]
	}
}

// BoolToBytes converts a Go bool to a CK_BBOOL byte slice.
func BoolToBytes(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// BytesToBool converts a CK_BBOOL byte slice to a Go bool.
func BytesToBool(b []byte) bool {
	return len(b) > 0 && b[0] != 0
}

// UlongToBytes converts a uint to a CK_ULONG byte slice (little-endian, platform-dependent).
func UlongToBytes(v uint) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

// BytesToUlong converts a CK_ULONG byte slice to uint.
func BytesToUlong(b []byte) uint {
	switch len(b) {
	case 4:
		return uint(binary.LittleEndian.Uint32(b))
	case 8:
		return uint(binary.LittleEndian.Uint64(b))
	default:
		return 0
	}
}

// EncodeBase64 encodes bytes to base64 standard encoding.
func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeBase64 decodes a base64 string to bytes.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeHex encodes a big integer byte slice to hex string.
func EncodeHex(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeHex decodes a hex string to bytes.
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// BigIntToBytes converts a big.Int to a byte slice (big-endian, unsigned).
func BigIntToBytes(n *big.Int) []byte {
	return n.Bytes()
}

// BytesToBigInt converts a byte slice to a big.Int.
func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// NewAttribute creates a pkcs11.Attribute from a type and value.
func NewAttribute(attrType uint, value interface{}) *pkcs11.Attribute {
	return pkcs11.NewAttribute(attrType, value)
}

// MechanismNameToID maps mechanism name strings to CKM_* constants.
var MechanismNameToID = map[string]uint{
	"CKM_RSA_PKCS_KEY_PAIR_GEN":          pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN,
	"CKM_RSA_PKCS":                       pkcs11.CKM_RSA_PKCS,
	"CKM_RSA_9796":                       pkcs11.CKM_RSA_9796,
	"CKM_RSA_X_509":                      pkcs11.CKM_RSA_X_509,
	"CKM_MD2_RSA_PKCS":                   pkcs11.CKM_MD2_RSA_PKCS,
	"CKM_MD5_RSA_PKCS":                   pkcs11.CKM_MD5_RSA_PKCS,
	"CKM_SHA1_RSA_PKCS":                  pkcs11.CKM_SHA1_RSA_PKCS,
	"CKM_RIPEMD128_RSA_PKCS":             pkcs11.CKM_RIPEMD128_RSA_PKCS,
	"CKM_RIPEMD160_RSA_PKCS":             pkcs11.CKM_RIPEMD160_RSA_PKCS,
	"CKM_RSA_PKCS_OAEP":                  pkcs11.CKM_RSA_PKCS_OAEP,
	"CKM_RSA_X9_31_KEY_PAIR_GEN":         pkcs11.CKM_RSA_X9_31_KEY_PAIR_GEN,
	"CKM_RSA_X9_31":                      pkcs11.CKM_RSA_X9_31,
	"CKM_SHA1_RSA_X9_31":                 pkcs11.CKM_SHA1_RSA_X9_31,
	"CKM_RSA_PKCS_PSS":                   pkcs11.CKM_RSA_PKCS_PSS,
	"CKM_SHA1_RSA_PKCS_PSS":              pkcs11.CKM_SHA1_RSA_PKCS_PSS,
	"CKM_DSA_KEY_PAIR_GEN":               pkcs11.CKM_DSA_KEY_PAIR_GEN,
	"CKM_DSA":                            pkcs11.CKM_DSA,
	"CKM_DSA_SHA1":                       pkcs11.CKM_DSA_SHA1,
	"CKM_DSA_SHA224":                     pkcs11.CKM_DSA_SHA224,
	"CKM_DSA_SHA256":                     pkcs11.CKM_DSA_SHA256,
	"CKM_DSA_SHA384":                     pkcs11.CKM_DSA_SHA384,
	"CKM_DSA_SHA512":                     pkcs11.CKM_DSA_SHA512,
	"CKM_DSA_SHA3_224":                   pkcs11.CKM_DSA_SHA3_224,
	"CKM_DSA_SHA3_256":                   pkcs11.CKM_DSA_SHA3_256,
	"CKM_DSA_SHA3_384":                   pkcs11.CKM_DSA_SHA3_384,
	"CKM_DSA_SHA3_512":                   pkcs11.CKM_DSA_SHA3_512,
	"CKM_DH_PKCS_KEY_PAIR_GEN":           pkcs11.CKM_DH_PKCS_KEY_PAIR_GEN,
	"CKM_DH_PKCS_DERIVE":                 pkcs11.CKM_DH_PKCS_DERIVE,
	"CKM_X9_42_DH_KEY_PAIR_GEN":          pkcs11.CKM_X9_42_DH_KEY_PAIR_GEN,
	"CKM_X9_42_DH_DERIVE":                pkcs11.CKM_X9_42_DH_DERIVE,
	"CKM_X9_42_DH_HYBRID_DERIVE":         pkcs11.CKM_X9_42_DH_HYBRID_DERIVE,
	"CKM_X9_42_MQV_DERIVE":               pkcs11.CKM_X9_42_MQV_DERIVE,
	"CKM_SHA256_RSA_PKCS":                pkcs11.CKM_SHA256_RSA_PKCS,
	"CKM_SHA384_RSA_PKCS":                pkcs11.CKM_SHA384_RSA_PKCS,
	"CKM_SHA512_RSA_PKCS":                pkcs11.CKM_SHA512_RSA_PKCS,
	"CKM_SHA256_RSA_PKCS_PSS":            pkcs11.CKM_SHA256_RSA_PKCS_PSS,
	"CKM_SHA384_RSA_PKCS_PSS":            pkcs11.CKM_SHA384_RSA_PKCS_PSS,
	"CKM_SHA512_RSA_PKCS_PSS":            pkcs11.CKM_SHA512_RSA_PKCS_PSS,
	"CKM_SHA224_RSA_PKCS":                pkcs11.CKM_SHA224_RSA_PKCS,
	"CKM_SHA224_RSA_PKCS_PSS":            pkcs11.CKM_SHA224_RSA_PKCS_PSS,
	"CKM_SHA512_224":                     pkcs11.CKM_SHA512_224,
	"CKM_SHA512_224_HMAC":                pkcs11.CKM_SHA512_224_HMAC,
	"CKM_SHA512_224_HMAC_GENERAL":        pkcs11.CKM_SHA512_224_HMAC_GENERAL,
	"CKM_SHA512_224_KEY_DERIVATION":      pkcs11.CKM_SHA512_224_KEY_DERIVATION,
	"CKM_SHA512_256":                     pkcs11.CKM_SHA512_256,
	"CKM_SHA512_256_HMAC":                pkcs11.CKM_SHA512_256_HMAC,
	"CKM_SHA512_256_HMAC_GENERAL":        pkcs11.CKM_SHA512_256_HMAC_GENERAL,
	"CKM_SHA512_256_KEY_DERIVATION":      pkcs11.CKM_SHA512_256_KEY_DERIVATION,
	"CKM_SHA512_T":                       pkcs11.CKM_SHA512_T,
	"CKM_SHA512_T_HMAC":                  pkcs11.CKM_SHA512_T_HMAC,
	"CKM_SHA512_T_HMAC_GENERAL":          pkcs11.CKM_SHA512_T_HMAC_GENERAL,
	"CKM_SHA512_T_KEY_DERIVATION":        pkcs11.CKM_SHA512_T_KEY_DERIVATION,
	"CKM_SHA3_256_RSA_PKCS":              pkcs11.CKM_SHA3_256_RSA_PKCS,
	"CKM_SHA3_384_RSA_PKCS":              pkcs11.CKM_SHA3_384_RSA_PKCS,
	"CKM_SHA3_512_RSA_PKCS":              pkcs11.CKM_SHA3_512_RSA_PKCS,
	"CKM_SHA3_256_RSA_PKCS_PSS":          pkcs11.CKM_SHA3_256_RSA_PKCS_PSS,
	"CKM_SHA3_384_RSA_PKCS_PSS":          pkcs11.CKM_SHA3_384_RSA_PKCS_PSS,
	"CKM_SHA3_512_RSA_PKCS_PSS":          pkcs11.CKM_SHA3_512_RSA_PKCS_PSS,
	"CKM_SHA3_224_RSA_PKCS":              pkcs11.CKM_SHA3_224_RSA_PKCS,
	"CKM_SHA3_224_RSA_PKCS_PSS":          pkcs11.CKM_SHA3_224_RSA_PKCS_PSS,
	"CKM_RC2_KEY_GEN":                    pkcs11.CKM_RC2_KEY_GEN,
	"CKM_RC2_ECB":                        pkcs11.CKM_RC2_ECB,
	"CKM_RC2_CBC":                        pkcs11.CKM_RC2_CBC,
	"CKM_RC2_MAC":                        pkcs11.CKM_RC2_MAC,
	"CKM_RC2_MAC_GENERAL":                pkcs11.CKM_RC2_MAC_GENERAL,
	"CKM_RC2_CBC_PAD":                    pkcs11.CKM_RC2_CBC_PAD,
	"CKM_RC4_KEY_GEN":                    pkcs11.CKM_RC4_KEY_GEN,
	"CKM_RC4":                            pkcs11.CKM_RC4,
	"CKM_DES_KEY_GEN":                    pkcs11.CKM_DES_KEY_GEN,
	"CKM_DES_ECB":                        pkcs11.CKM_DES_ECB,
	"CKM_DES_CBC":                        pkcs11.CKM_DES_CBC,
	"CKM_DES_MAC":                        pkcs11.CKM_DES_MAC,
	"CKM_DES_MAC_GENERAL":                pkcs11.CKM_DES_MAC_GENERAL,
	"CKM_DES_CBC_PAD":                    pkcs11.CKM_DES_CBC_PAD,
	"CKM_DES2_KEY_GEN":                   pkcs11.CKM_DES2_KEY_GEN,
	"CKM_DES3_KEY_GEN":                   pkcs11.CKM_DES3_KEY_GEN,
	"CKM_DES3_ECB":                       pkcs11.CKM_DES3_ECB,
	"CKM_DES3_CBC":                       pkcs11.CKM_DES3_CBC,
	"CKM_DES3_MAC":                       pkcs11.CKM_DES3_MAC,
	"CKM_DES3_MAC_GENERAL":               pkcs11.CKM_DES3_MAC_GENERAL,
	"CKM_DES3_CBC_PAD":                   pkcs11.CKM_DES3_CBC_PAD,
	"CKM_DES3_CMAC_GENERAL":              pkcs11.CKM_DES3_CMAC_GENERAL,
	"CKM_DES3_CMAC":                      pkcs11.CKM_DES3_CMAC,
	"CKM_CDMF_KEY_GEN":                   pkcs11.CKM_CDMF_KEY_GEN,
	"CKM_CDMF_ECB":                       pkcs11.CKM_CDMF_ECB,
	"CKM_CDMF_CBC":                       pkcs11.CKM_CDMF_CBC,
	"CKM_CDMF_MAC":                       pkcs11.CKM_CDMF_MAC,
	"CKM_CDMF_MAC_GENERAL":               pkcs11.CKM_CDMF_MAC_GENERAL,
	"CKM_CDMF_CBC_PAD":                   pkcs11.CKM_CDMF_CBC_PAD,
	"CKM_DES_OFB64":                      pkcs11.CKM_DES_OFB64,
	"CKM_DES_OFB8":                       pkcs11.CKM_DES_OFB8,
	"CKM_DES_CFB64":                      pkcs11.CKM_DES_CFB64,
	"CKM_DES_CFB8":                       pkcs11.CKM_DES_CFB8,
	"CKM_MD2":                            pkcs11.CKM_MD2,
	"CKM_MD2_HMAC":                       pkcs11.CKM_MD2_HMAC,
	"CKM_MD2_HMAC_GENERAL":               pkcs11.CKM_MD2_HMAC_GENERAL,
	"CKM_MD5":                            pkcs11.CKM_MD5,
	"CKM_MD5_HMAC":                       pkcs11.CKM_MD5_HMAC,
	"CKM_MD5_HMAC_GENERAL":               pkcs11.CKM_MD5_HMAC_GENERAL,
	"CKM_SHA_1":                          pkcs11.CKM_SHA_1,
	"CKM_SHA_1_HMAC":                     pkcs11.CKM_SHA_1_HMAC,
	"CKM_SHA_1_HMAC_GENERAL":             pkcs11.CKM_SHA_1_HMAC_GENERAL,
	"CKM_RIPEMD128":                      pkcs11.CKM_RIPEMD128,
	"CKM_RIPEMD128_HMAC":                 pkcs11.CKM_RIPEMD128_HMAC,
	"CKM_RIPEMD128_HMAC_GENERAL":         pkcs11.CKM_RIPEMD128_HMAC_GENERAL,
	"CKM_RIPEMD160":                      pkcs11.CKM_RIPEMD160,
	"CKM_RIPEMD160_HMAC":                 pkcs11.CKM_RIPEMD160_HMAC,
	"CKM_RIPEMD160_HMAC_GENERAL":         pkcs11.CKM_RIPEMD160_HMAC_GENERAL,
	"CKM_SHA256":                         pkcs11.CKM_SHA256,
	"CKM_SHA256_HMAC":                    pkcs11.CKM_SHA256_HMAC,
	"CKM_SHA256_HMAC_GENERAL":            pkcs11.CKM_SHA256_HMAC_GENERAL,
	"CKM_SHA224":                         pkcs11.CKM_SHA224,
	"CKM_SHA224_HMAC":                    pkcs11.CKM_SHA224_HMAC,
	"CKM_SHA224_HMAC_GENERAL":            pkcs11.CKM_SHA224_HMAC_GENERAL,
	"CKM_SHA384":                         pkcs11.CKM_SHA384,
	"CKM_SHA384_HMAC":                    pkcs11.CKM_SHA384_HMAC,
	"CKM_SHA384_HMAC_GENERAL":            pkcs11.CKM_SHA384_HMAC_GENERAL,
	"CKM_SHA512":                         pkcs11.CKM_SHA512,
	"CKM_SHA512_HMAC":                    pkcs11.CKM_SHA512_HMAC,
	"CKM_SHA512_HMAC_GENERAL":            pkcs11.CKM_SHA512_HMAC_GENERAL,
	"CKM_SECURID_KEY_GEN":                pkcs11.CKM_SECURID_KEY_GEN,
	"CKM_SECURID":                        pkcs11.CKM_SECURID,
	"CKM_HOTP_KEY_GEN":                   pkcs11.CKM_HOTP_KEY_GEN,
	"CKM_HOTP":                           pkcs11.CKM_HOTP,
	"CKM_ACTI":                           pkcs11.CKM_ACTI,
	"CKM_ACTI_KEY_GEN":                   pkcs11.CKM_ACTI_KEY_GEN,
	"CKM_SHA3_256":                       pkcs11.CKM_SHA3_256,
	"CKM_SHA3_256_HMAC":                  pkcs11.CKM_SHA3_256_HMAC,
	"CKM_SHA3_256_HMAC_GENERAL":          pkcs11.CKM_SHA3_256_HMAC_GENERAL,
	"CKM_SHA3_256_KEY_GEN":               pkcs11.CKM_SHA3_256_KEY_GEN,
	"CKM_SHA3_224":                       pkcs11.CKM_SHA3_224,
	"CKM_SHA3_224_HMAC":                  pkcs11.CKM_SHA3_224_HMAC,
	"CKM_SHA3_224_HMAC_GENERAL":          pkcs11.CKM_SHA3_224_HMAC_GENERAL,
	"CKM_SHA3_224_KEY_GEN":               pkcs11.CKM_SHA3_224_KEY_GEN,
	"CKM_SHA3_384":                       pkcs11.CKM_SHA3_384,
	"CKM_SHA3_384_HMAC":                  pkcs11.CKM_SHA3_384_HMAC,
	"CKM_SHA3_384_HMAC_GENERAL":          pkcs11.CKM_SHA3_384_HMAC_GENERAL,
	"CKM_SHA3_384_KEY_GEN":               pkcs11.CKM_SHA3_384_KEY_GEN,
	"CKM_SHA3_512":                       pkcs11.CKM_SHA3_512,
	"CKM_SHA3_512_HMAC":                  pkcs11.CKM_SHA3_512_HMAC,
	"CKM_SHA3_512_HMAC_GENERAL":          pkcs11.CKM_SHA3_512_HMAC_GENERAL,
	"CKM_SHA3_512_KEY_GEN":               pkcs11.CKM_SHA3_512_KEY_GEN,
	"CKM_CAST_KEY_GEN":                   pkcs11.CKM_CAST_KEY_GEN,
	"CKM_CAST_ECB":                       pkcs11.CKM_CAST_ECB,
	"CKM_CAST_CBC":                       pkcs11.CKM_CAST_CBC,
	"CKM_CAST_MAC":                       pkcs11.CKM_CAST_MAC,
	"CKM_CAST_MAC_GENERAL":               pkcs11.CKM_CAST_MAC_GENERAL,
	"CKM_CAST_CBC_PAD":                   pkcs11.CKM_CAST_CBC_PAD,
	"CKM_CAST3_KEY_GEN":                  pkcs11.CKM_CAST3_KEY_GEN,
	"CKM_CAST3_ECB":                      pkcs11.CKM_CAST3_ECB,
	"CKM_CAST3_CBC":                      pkcs11.CKM_CAST3_CBC,
	"CKM_CAST3_MAC":                      pkcs11.CKM_CAST3_MAC,
	"CKM_CAST3_MAC_GENERAL":              pkcs11.CKM_CAST3_MAC_GENERAL,
	"CKM_CAST3_CBC_PAD":                  pkcs11.CKM_CAST3_CBC_PAD,
	"CKM_CAST5_KEY_GEN":                  pkcs11.CKM_CAST5_KEY_GEN,
	"CKM_CAST128_KEY_GEN":                pkcs11.CKM_CAST128_KEY_GEN,
	"CKM_CAST5_ECB":                      pkcs11.CKM_CAST5_ECB,
	"CKM_CAST128_ECB":                    pkcs11.CKM_CAST128_ECB,
	"CKM_CAST5_CBC":                      pkcs11.CKM_CAST5_CBC,
	"CKM_CAST128_CBC":                    pkcs11.CKM_CAST128_CBC,
	"CKM_CAST5_MAC":                      pkcs11.CKM_CAST5_MAC,
	"CKM_CAST128_MAC":                    pkcs11.CKM_CAST128_MAC,
	"CKM_CAST5_MAC_GENERAL":              pkcs11.CKM_CAST5_MAC_GENERAL,
	"CKM_CAST128_MAC_GENERAL":            pkcs11.CKM_CAST128_MAC_GENERAL,
	"CKM_CAST5_CBC_PAD":                  pkcs11.CKM_CAST5_CBC_PAD,
	"CKM_CAST128_CBC_PAD":                pkcs11.CKM_CAST128_CBC_PAD,
	"CKM_RC5_KEY_GEN":                    pkcs11.CKM_RC5_KEY_GEN,
	"CKM_RC5_ECB":                        pkcs11.CKM_RC5_ECB,
	"CKM_RC5_CBC":                        pkcs11.CKM_RC5_CBC,
	"CKM_RC5_MAC":                        pkcs11.CKM_RC5_MAC,
	"CKM_RC5_MAC_GENERAL":                pkcs11.CKM_RC5_MAC_GENERAL,
	"CKM_RC5_CBC_PAD":                    pkcs11.CKM_RC5_CBC_PAD,
	"CKM_IDEA_KEY_GEN":                   pkcs11.CKM_IDEA_KEY_GEN,
	"CKM_IDEA_ECB":                       pkcs11.CKM_IDEA_ECB,
	"CKM_IDEA_CBC":                       pkcs11.CKM_IDEA_CBC,
	"CKM_IDEA_MAC":                       pkcs11.CKM_IDEA_MAC,
	"CKM_IDEA_MAC_GENERAL":               pkcs11.CKM_IDEA_MAC_GENERAL,
	"CKM_IDEA_CBC_PAD":                   pkcs11.CKM_IDEA_CBC_PAD,
	"CKM_GENERIC_SECRET_KEY_GEN":         pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
	"CKM_CONCATENATE_BASE_AND_KEY":       pkcs11.CKM_CONCATENATE_BASE_AND_KEY,
	"CKM_CONCATENATE_BASE_AND_DATA":      pkcs11.CKM_CONCATENATE_BASE_AND_DATA,
	"CKM_CONCATENATE_DATA_AND_BASE":      pkcs11.CKM_CONCATENATE_DATA_AND_BASE,
	"CKM_XOR_BASE_AND_DATA":              pkcs11.CKM_XOR_BASE_AND_DATA,
	"CKM_EXTRACT_KEY_FROM_KEY":           pkcs11.CKM_EXTRACT_KEY_FROM_KEY,
	"CKM_SSL3_PRE_MASTER_KEY_GEN":        pkcs11.CKM_SSL3_PRE_MASTER_KEY_GEN,
	"CKM_SSL3_MASTER_KEY_DERIVE":         pkcs11.CKM_SSL3_MASTER_KEY_DERIVE,
	"CKM_SSL3_KEY_AND_MAC_DERIVE":        pkcs11.CKM_SSL3_KEY_AND_MAC_DERIVE,
	"CKM_SSL3_MASTER_KEY_DERIVE_DH":      pkcs11.CKM_SSL3_MASTER_KEY_DERIVE_DH,
	"CKM_TLS_PRE_MASTER_KEY_GEN":         pkcs11.CKM_TLS_PRE_MASTER_KEY_GEN,
	"CKM_TLS_MASTER_KEY_DERIVE":          pkcs11.CKM_TLS_MASTER_KEY_DERIVE,
	"CKM_TLS_KEY_AND_MAC_DERIVE":         pkcs11.CKM_TLS_KEY_AND_MAC_DERIVE,
	"CKM_TLS_MASTER_KEY_DERIVE_DH":       pkcs11.CKM_TLS_MASTER_KEY_DERIVE_DH,
	"CKM_TLS_PRF":                        pkcs11.CKM_TLS_PRF,
	"CKM_SSL3_MD5_MAC":                   pkcs11.CKM_SSL3_MD5_MAC,
	"CKM_SSL3_SHA1_MAC":                  pkcs11.CKM_SSL3_SHA1_MAC,
	"CKM_MD5_KEY_DERIVATION":             pkcs11.CKM_MD5_KEY_DERIVATION,
	"CKM_MD2_KEY_DERIVATION":             pkcs11.CKM_MD2_KEY_DERIVATION,
	"CKM_SHA1_KEY_DERIVATION":            pkcs11.CKM_SHA1_KEY_DERIVATION,
	"CKM_SHA256_KEY_DERIVATION":          pkcs11.CKM_SHA256_KEY_DERIVATION,
	"CKM_SHA384_KEY_DERIVATION":          pkcs11.CKM_SHA384_KEY_DERIVATION,
	"CKM_SHA512_KEY_DERIVATION":          pkcs11.CKM_SHA512_KEY_DERIVATION,
	"CKM_SHA224_KEY_DERIVATION":          pkcs11.CKM_SHA224_KEY_DERIVATION,
	"CKM_SHA3_256_KEY_DERIVE":            pkcs11.CKM_SHA3_256_KEY_DERIVE,
	"CKM_SHA3_224_KEY_DERIVE":            pkcs11.CKM_SHA3_224_KEY_DERIVE,
	"CKM_SHA3_384_KEY_DERIVE":            pkcs11.CKM_SHA3_384_KEY_DERIVE,
	"CKM_SHA3_512_KEY_DERIVE":            pkcs11.CKM_SHA3_512_KEY_DERIVE,
	"CKM_SHAKE_128_KEY_DERIVE":           pkcs11.CKM_SHAKE_128_KEY_DERIVE,
	"CKM_SHAKE_256_KEY_DERIVE":           pkcs11.CKM_SHAKE_256_KEY_DERIVE,
	"CKM_PBE_MD2_DES_CBC":                pkcs11.CKM_PBE_MD2_DES_CBC,
	"CKM_PBE_MD5_DES_CBC":                pkcs11.CKM_PBE_MD5_DES_CBC,
	"CKM_PBE_MD5_CAST_CBC":               pkcs11.CKM_PBE_MD5_CAST_CBC,
	"CKM_PBE_MD5_CAST3_CBC":              pkcs11.CKM_PBE_MD5_CAST3_CBC,
	"CKM_PBE_MD5_CAST5_CBC":              pkcs11.CKM_PBE_MD5_CAST5_CBC,
	"CKM_PBE_MD5_CAST128_CBC":            pkcs11.CKM_PBE_MD5_CAST128_CBC,
	"CKM_PBE_SHA1_CAST5_CBC":             pkcs11.CKM_PBE_SHA1_CAST5_CBC,
	"CKM_PBE_SHA1_CAST128_CBC":           pkcs11.CKM_PBE_SHA1_CAST128_CBC,
	"CKM_PBE_SHA1_RC4_128":               pkcs11.CKM_PBE_SHA1_RC4_128,
	"CKM_PBE_SHA1_RC4_40":                pkcs11.CKM_PBE_SHA1_RC4_40,
	"CKM_PBE_SHA1_DES3_EDE_CBC":          pkcs11.CKM_PBE_SHA1_DES3_EDE_CBC,
	"CKM_PBE_SHA1_DES2_EDE_CBC":          pkcs11.CKM_PBE_SHA1_DES2_EDE_CBC,
	"CKM_PBE_SHA1_RC2_128_CBC":           pkcs11.CKM_PBE_SHA1_RC2_128_CBC,
	"CKM_PBE_SHA1_RC2_40_CBC":            pkcs11.CKM_PBE_SHA1_RC2_40_CBC,
	"CKM_PKCS5_PBKD2":                    pkcs11.CKM_PKCS5_PBKD2,
	"CKM_PBA_SHA1_WITH_SHA1_HMAC":        pkcs11.CKM_PBA_SHA1_WITH_SHA1_HMAC,
	"CKM_WTLS_PRE_MASTER_KEY_GEN":        pkcs11.CKM_WTLS_PRE_MASTER_KEY_GEN,
	"CKM_WTLS_MASTER_KEY_DERIVE":         pkcs11.CKM_WTLS_MASTER_KEY_DERIVE,
	"CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC":  pkcs11.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
	"CKM_WTLS_PRF":                       pkcs11.CKM_WTLS_PRF,
	"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE": pkcs11.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
	"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE": pkcs11.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
	"CKM_TLS10_MAC_SERVER":               pkcs11.CKM_TLS10_MAC_SERVER,
	"CKM_TLS10_MAC_CLIENT":               pkcs11.CKM_TLS10_MAC_CLIENT,
	"CKM_TLS12_MAC":                      pkcs11.CKM_TLS12_MAC,
	"CKM_TLS12_KDF":                      pkcs11.CKM_TLS12_KDF,
	"CKM_TLS12_MASTER_KEY_DERIVE":        pkcs11.CKM_TLS12_MASTER_KEY_DERIVE,
	"CKM_TLS12_KEY_AND_MAC_DERIVE":       pkcs11.CKM_TLS12_KEY_AND_MAC_DERIVE,
	"CKM_TLS12_MASTER_KEY_DERIVE_DH":     pkcs11.CKM_TLS12_MASTER_KEY_DERIVE_DH,
	"CKM_TLS12_KEY_SAFE_DERIVE":          pkcs11.CKM_TLS12_KEY_SAFE_DERIVE,
	"CKM_TLS_MAC":                        pkcs11.CKM_TLS_MAC,
	"CKM_TLS_KDF":                        pkcs11.CKM_TLS_KDF,
	"CKM_KEY_WRAP_LYNKS":                 pkcs11.CKM_KEY_WRAP_LYNKS,
	"CKM_KEY_WRAP_SET_OAEP":              pkcs11.CKM_KEY_WRAP_SET_OAEP,
	"CKM_CMS_SIG":                        pkcs11.CKM_CMS_SIG,
	"CKM_KIP_DERIVE":                     pkcs11.CKM_KIP_DERIVE,
	"CKM_KIP_WRAP":                       pkcs11.CKM_KIP_WRAP,
	"CKM_KIP_MAC":                        pkcs11.CKM_KIP_MAC,
	"CKM_CAMELLIA_KEY_GEN":               pkcs11.CKM_CAMELLIA_KEY_GEN,
	"CKM_CAMELLIA_ECB":                   pkcs11.CKM_CAMELLIA_ECB,
	"CKM_CAMELLIA_CBC":                   pkcs11.CKM_CAMELLIA_CBC,
	"CKM_CAMELLIA_MAC":                   pkcs11.CKM_CAMELLIA_MAC,
	"CKM_CAMELLIA_MAC_GENERAL":           pkcs11.CKM_CAMELLIA_MAC_GENERAL,
	"CKM_CAMELLIA_CBC_PAD":               pkcs11.CKM_CAMELLIA_CBC_PAD,
	"CKM_CAMELLIA_ECB_ENCRYPT_DATA":      pkcs11.CKM_CAMELLIA_ECB_ENCRYPT_DATA,
	"CKM_CAMELLIA_CBC_ENCRYPT_DATA":      pkcs11.CKM_CAMELLIA_CBC_ENCRYPT_DATA,
	"CKM_CAMELLIA_CTR":                   pkcs11.CKM_CAMELLIA_CTR,
	"CKM_ARIA_KEY_GEN":                   pkcs11.CKM_ARIA_KEY_GEN,
	"CKM_ARIA_ECB":                       pkcs11.CKM_ARIA_ECB,
	"CKM_ARIA_CBC":                       pkcs11.CKM_ARIA_CBC,
	"CKM_ARIA_MAC":                       pkcs11.CKM_ARIA_MAC,
	"CKM_ARIA_MAC_GENERAL":               pkcs11.CKM_ARIA_MAC_GENERAL,
	"CKM_ARIA_CBC_PAD":                   pkcs11.CKM_ARIA_CBC_PAD,
	"CKM_ARIA_ECB_ENCRYPT_DATA":          pkcs11.CKM_ARIA_ECB_ENCRYPT_DATA,
	"CKM_ARIA_CBC_ENCRYPT_DATA":          pkcs11.CKM_ARIA_CBC_ENCRYPT_DATA,
	"CKM_SEED_KEY_GEN":                   pkcs11.CKM_SEED_KEY_GEN,
	"CKM_SEED_ECB":                       pkcs11.CKM_SEED_ECB,
	"CKM_SEED_CBC":                       pkcs11.CKM_SEED_CBC,
	"CKM_SEED_MAC":                       pkcs11.CKM_SEED_MAC,
	"CKM_SEED_MAC_GENERAL":               pkcs11.CKM_SEED_MAC_GENERAL,
	"CKM_SEED_CBC_PAD":                   pkcs11.CKM_SEED_CBC_PAD,
	"CKM_SEED_ECB_ENCRYPT_DATA":          pkcs11.CKM_SEED_ECB_ENCRYPT_DATA,
	"CKM_SEED_CBC_ENCRYPT_DATA":          pkcs11.CKM_SEED_CBC_ENCRYPT_DATA,
	"CKM_SKIPJACK_KEY_GEN":               pkcs11.CKM_SKIPJACK_KEY_GEN,
	"CKM_SKIPJACK_ECB64":                 pkcs11.CKM_SKIPJACK_ECB64,
	"CKM_SKIPJACK_CBC64":                 pkcs11.CKM_SKIPJACK_CBC64,
	"CKM_SKIPJACK_OFB64":                 pkcs11.CKM_SKIPJACK_OFB64,
	"CKM_SKIPJACK_CFB64":                 pkcs11.CKM_SKIPJACK_CFB64,
	"CKM_SKIPJACK_CFB32":                 pkcs11.CKM_SKIPJACK_CFB32,
	"CKM_SKIPJACK_CFB16":                 pkcs11.CKM_SKIPJACK_CFB16,
	"CKM_SKIPJACK_CFB8":                  pkcs11.CKM_SKIPJACK_CFB8,
	"CKM_SKIPJACK_WRAP":                  pkcs11.CKM_SKIPJACK_WRAP,
	"CKM_SKIPJACK_PRIVATE_WRAP":          pkcs11.CKM_SKIPJACK_PRIVATE_WRAP,
	"CKM_SKIPJACK_RELAYX":                pkcs11.CKM_SKIPJACK_RELAYX,
	"CKM_KEA_KEY_PAIR_GEN":               pkcs11.CKM_KEA_KEY_PAIR_GEN,
	"CKM_KEA_KEY_DERIVE":                 pkcs11.CKM_KEA_KEY_DERIVE,
	"CKM_KEA_DERIVE":                     pkcs11.CKM_KEA_DERIVE,
	"CKM_FORTEZZA_TIMESTAMP":             pkcs11.CKM_FORTEZZA_TIMESTAMP,
	"CKM_BATON_KEY_GEN":                  pkcs11.CKM_BATON_KEY_GEN,
	"CKM_BATON_ECB128":                   pkcs11.CKM_BATON_ECB128,
	"CKM_BATON_ECB96":                    pkcs11.CKM_BATON_ECB96,
	"CKM_BATON_CBC128":                   pkcs11.CKM_BATON_CBC128,
	"CKM_BATON_COUNTER":                  pkcs11.CKM_BATON_COUNTER,
	"CKM_BATON_SHUFFLE":                  pkcs11.CKM_BATON_SHUFFLE,
	"CKM_BATON_WRAP":                     pkcs11.CKM_BATON_WRAP,
	"CKM_EC_KEY_PAIR_GEN":                pkcs11.CKM_EC_KEY_PAIR_GEN,
	"CKM_ECDSA":                          pkcs11.CKM_ECDSA,
	"CKM_ECDSA_SHA1":                     pkcs11.CKM_ECDSA_SHA1,
	"CKM_ECDSA_SHA224":                   pkcs11.CKM_ECDSA_SHA224,
	"CKM_ECDSA_SHA256":                   pkcs11.CKM_ECDSA_SHA256,
	"CKM_ECDSA_SHA384":                   pkcs11.CKM_ECDSA_SHA384,
	"CKM_ECDSA_SHA512":                   pkcs11.CKM_ECDSA_SHA512,
	"CKM_ECDH1_DERIVE":                   pkcs11.CKM_ECDH1_DERIVE,
	"CKM_ECDH1_COFACTOR_DERIVE":          pkcs11.CKM_ECDH1_COFACTOR_DERIVE,
	"CKM_ECMQV_DERIVE":                   pkcs11.CKM_ECMQV_DERIVE,
	"CKM_ECDH_AES_KEY_WRAP":              pkcs11.CKM_ECDH_AES_KEY_WRAP,
	"CKM_RSA_AES_KEY_WRAP":               pkcs11.CKM_RSA_AES_KEY_WRAP,
	"CKM_JUNIPER_KEY_GEN":                pkcs11.CKM_JUNIPER_KEY_GEN,
	"CKM_JUNIPER_ECB128":                 pkcs11.CKM_JUNIPER_ECB128,
	"CKM_JUNIPER_CBC128":                 pkcs11.CKM_JUNIPER_CBC128,
	"CKM_JUNIPER_COUNTER":                pkcs11.CKM_JUNIPER_COUNTER,
	"CKM_JUNIPER_SHUFFLE":                pkcs11.CKM_JUNIPER_SHUFFLE,
	"CKM_JUNIPER_WRAP":                   pkcs11.CKM_JUNIPER_WRAP,
	"CKM_FASTHASH":                       pkcs11.CKM_FASTHASH,
	"CKM_AES_KEY_GEN":                    pkcs11.CKM_AES_KEY_GEN,
	"CKM_AES_ECB":                        pkcs11.CKM_AES_ECB,
	"CKM_AES_CBC":                        pkcs11.CKM_AES_CBC,
	"CKM_AES_MAC":                        pkcs11.CKM_AES_MAC,
	"CKM_AES_MAC_GENERAL":                pkcs11.CKM_AES_MAC_GENERAL,
	"CKM_AES_CBC_PAD":                    pkcs11.CKM_AES_CBC_PAD,
	"CKM_AES_CTR":                        pkcs11.CKM_AES_CTR,
	"CKM_AES_GCM":                        pkcs11.CKM_AES_GCM,
	"CKM_AES_CCM":                        pkcs11.CKM_AES_CCM,
	"CKM_AES_CTS":                        pkcs11.CKM_AES_CTS,
	"CKM_AES_CMAC":                       pkcs11.CKM_AES_CMAC,
	"CKM_AES_CMAC_GENERAL":               pkcs11.CKM_AES_CMAC_GENERAL,
	"CKM_AES_XCBC_MAC":                   pkcs11.CKM_AES_XCBC_MAC,
	"CKM_AES_XCBC_MAC_96":                pkcs11.CKM_AES_XCBC_MAC_96,
	"CKM_AES_GMAC":                       pkcs11.CKM_AES_GMAC,
	"CKM_BLOWFISH_KEY_GEN":               pkcs11.CKM_BLOWFISH_KEY_GEN,
	"CKM_BLOWFISH_CBC":                   pkcs11.CKM_BLOWFISH_CBC,
	"CKM_TWOFISH_KEY_GEN":                pkcs11.CKM_TWOFISH_KEY_GEN,
	"CKM_TWOFISH_CBC":                    pkcs11.CKM_TWOFISH_CBC,
	"CKM_BLOWFISH_CBC_PAD":               pkcs11.CKM_BLOWFISH_CBC_PAD,
	"CKM_TWOFISH_CBC_PAD":                pkcs11.CKM_TWOFISH_CBC_PAD,
	"CKM_DES_ECB_ENCRYPT_DATA":           pkcs11.CKM_DES_ECB_ENCRYPT_DATA,
	"CKM_DES_CBC_ENCRYPT_DATA":           pkcs11.CKM_DES_CBC_ENCRYPT_DATA,
	"CKM_DES3_ECB_ENCRYPT_DATA":          pkcs11.CKM_DES3_ECB_ENCRYPT_DATA,
	"CKM_DES3_CBC_ENCRYPT_DATA":          pkcs11.CKM_DES3_CBC_ENCRYPT_DATA,
	"CKM_AES_ECB_ENCRYPT_DATA":           pkcs11.CKM_AES_ECB_ENCRYPT_DATA,
	"CKM_AES_CBC_ENCRYPT_DATA":           pkcs11.CKM_AES_CBC_ENCRYPT_DATA,
	"CKM_GOSTR3410_KEY_PAIR_GEN":         pkcs11.CKM_GOSTR3410_KEY_PAIR_GEN,
	"CKM_GOSTR3410":                      pkcs11.CKM_GOSTR3410,
	"CKM_GOSTR3410_WITH_GOSTR3411":       pkcs11.CKM_GOSTR3410_WITH_GOSTR3411,
	"CKM_GOSTR3410_KEY_WRAP":             pkcs11.CKM_GOSTR3410_KEY_WRAP,
	"CKM_GOSTR3410_DERIVE":               pkcs11.CKM_GOSTR3410_DERIVE,
	"CKM_GOSTR3411":                      pkcs11.CKM_GOSTR3411,
	"CKM_GOSTR3411_HMAC":                 pkcs11.CKM_GOSTR3411_HMAC,
	"CKM_GOST28147_KEY_GEN":              pkcs11.CKM_GOST28147_KEY_GEN,
	"CKM_GOST28147_ECB":                  pkcs11.CKM_GOST28147_ECB,
	"CKM_GOST28147":                      pkcs11.CKM_GOST28147,
	"CKM_GOST28147_MAC":                  pkcs11.CKM_GOST28147_MAC,
	"CKM_GOST28147_KEY_WRAP":             pkcs11.CKM_GOST28147_KEY_WRAP,
	"CKM_DSA_PARAMETER_GEN":              pkcs11.CKM_DSA_PARAMETER_GEN,
	"CKM_DH_PKCS_PARAMETER_GEN":          pkcs11.CKM_DH_PKCS_PARAMETER_GEN,
	"CKM_X9_42_DH_PARAMETER_GEN":         pkcs11.CKM_X9_42_DH_PARAMETER_GEN,
	"CKM_DSA_PROBABLISTIC_PARAMETER_GEN": pkcs11.CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
	"CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN": pkcs11.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
	"CKM_AES_OFB":                        pkcs11.CKM_AES_OFB,
	"CKM_AES_CFB64":                      pkcs11.CKM_AES_CFB64,
	"CKM_AES_CFB8":                       pkcs11.CKM_AES_CFB8,
	"CKM_AES_CFB128":                     pkcs11.CKM_AES_CFB128,
	"CKM_AES_CFB1":                       pkcs11.CKM_AES_CFB1,
	"CKM_AES_KEY_WRAP":                   pkcs11.CKM_AES_KEY_WRAP,
	"CKM_AES_KEY_WRAP_PAD":               pkcs11.CKM_AES_KEY_WRAP_PAD,
	"CKM_RSA_PKCS_TPM_1_1":               pkcs11.CKM_RSA_PKCS_TPM_1_1,
	"CKM_RSA_PKCS_OAEP_TPM_1_1":          pkcs11.CKM_RSA_PKCS_OAEP_TPM_1_1,
	"CKM_VENDOR_DEFINED":                 pkcs11.CKM_VENDOR_DEFINED,
}

// MechanismIDToName is the reverse mapping.
var MechanismIDToName map[uint]string

func init() {
	MechanismIDToName = make(map[uint]string, len(MechanismNameToID))
	for name, id := range MechanismNameToID {
		MechanismIDToName[id] = name
	}
}

// KeyTypeNameToID maps key type names to CKK_* constants.
var KeyTypeNameToID = map[string]uint{
	"CKK_RSA":            pkcs11.CKK_RSA,
	"CKK_DSA":            pkcs11.CKK_DSA,
	"CKK_DH":             pkcs11.CKK_DH,
	"CKK_ECDSA":          pkcs11.CKK_ECDSA,
	"CKK_EC":             pkcs11.CKK_EC,
	"CKK_X9_42_DH":       pkcs11.CKK_X9_42_DH,
	"CKK_KEA":            pkcs11.CKK_KEA,
	"CKK_GENERIC_SECRET": pkcs11.CKK_GENERIC_SECRET,
	"CKK_RC2":            pkcs11.CKK_RC2,
	"CKK_RC4":            pkcs11.CKK_RC4,
	"CKK_DES":            pkcs11.CKK_DES,
	"CKK_DES2":           pkcs11.CKK_DES2,
	"CKK_DES3":           pkcs11.CKK_DES3,
	"CKK_CAST":           pkcs11.CKK_CAST,
	"CKK_CAST3":          pkcs11.CKK_CAST3,
	"CKK_CAST5":          pkcs11.CKK_CAST5,
	"CKK_CAST128":        pkcs11.CKK_CAST128,
	"CKK_RC5":            pkcs11.CKK_RC5,
	"CKK_IDEA":           pkcs11.CKK_IDEA,
	"CKK_SKIPJACK":       pkcs11.CKK_SKIPJACK,
	"CKK_BATON":          pkcs11.CKK_BATON,
	"CKK_JUNIPER":        pkcs11.CKK_JUNIPER,
	"CKK_CDMF":           pkcs11.CKK_CDMF,
	"CKK_AES":            pkcs11.CKK_AES,
	"CKK_BLOWFISH":       pkcs11.CKK_BLOWFISH,
	"CKK_TWOFISH":        pkcs11.CKK_TWOFISH,
	"CKK_SECURID":        pkcs11.CKK_SECURID,
	"CKK_HOTP":           pkcs11.CKK_HOTP,
	"CKK_ACTI":           pkcs11.CKK_ACTI,
	"CKK_CAMELLIA":       pkcs11.CKK_CAMELLIA,
	"CKK_ARIA":           pkcs11.CKK_ARIA,
	"CKK_MD5_HMAC":       pkcs11.CKK_MD5_HMAC,
	"CKK_SHA_1_HMAC":     pkcs11.CKK_SHA_1_HMAC,
	"CKK_RIPEMD128_HMAC": pkcs11.CKK_RIPEMD128_HMAC,
	"CKK_RIPEMD160_HMAC": pkcs11.CKK_RIPEMD160_HMAC,
	"CKK_SHA256_HMAC":    pkcs11.CKK_SHA256_HMAC,
	"CKK_SHA384_HMAC":    pkcs11.CKK_SHA384_HMAC,
	"CKK_SHA512_HMAC":    pkcs11.CKK_SHA512_HMAC,
	"CKK_SHA224_HMAC":    pkcs11.CKK_SHA224_HMAC,
	"CKK_SEED":           pkcs11.CKK_SEED,
	"CKK_GOSTR3410":      pkcs11.CKK_GOSTR3410,
	"CKK_GOSTR3411":      pkcs11.CKK_GOSTR3411,
	"CKK_GOST28147":      pkcs11.CKK_GOST28147,
	"CKK_SHA3_224_HMAC":  pkcs11.CKK_SHA3_224_HMAC,
	"CKK_SHA3_256_HMAC":  pkcs11.CKK_SHA3_256_HMAC,
	"CKK_SHA3_384_HMAC":  pkcs11.CKK_SHA3_384_HMAC,
	"CKK_SHA3_512_HMAC":  pkcs11.CKK_SHA3_512_HMAC,
	"CKK_VENDOR_DEFINED": pkcs11.CKK_VENDOR_DEFINED,
}

// KeyTypeIDToName is the reverse mapping.
var KeyTypeIDToName map[uint]string

func init() {
	KeyTypeIDToName = make(map[uint]string, len(KeyTypeNameToID))
	for name, id := range KeyTypeNameToID {
		KeyTypeIDToName[id] = name
	}
}

// ObjectClassNameToID maps object class names to CKO_* constants.
var ObjectClassNameToID = map[string]uint{
	"CKO_DATA":        pkcs11.CKO_DATA,
	"CKO_CERTIFICATE": pkcs11.CKO_CERTIFICATE,
	"CKO_PUBLIC_KEY":  pkcs11.CKO_PUBLIC_KEY,
	"CKO_PRIVATE_KEY": pkcs11.CKO_PRIVATE_KEY,
	"CKO_SECRET_KEY":  pkcs11.CKO_SECRET_KEY,
}

// ObjectClassIDToName is the reverse mapping.
var ObjectClassIDToName map[uint]string

func init() {
	ObjectClassIDToName = make(map[uint]string, len(ObjectClassNameToID))
	for name, id := range ObjectClassNameToID {
		ObjectClassIDToName[id] = name
	}
}

// FormatObjectID creates a composite resource ID from label, hex-encoded CKA_ID, and class name.
func FormatObjectID(label string, ckaID []byte, class uint) string {
	className := ObjectClassIDToName[class]
	if className == "" {
		className = fmt.Sprintf("0x%08X", class)
	}
	return fmt.Sprintf("%s/%s/%s", label, EncodeHex(ckaID), className)
}

// CertTypeNameToID maps certificate type names to CKC_* constants.
var CertTypeNameToID = map[string]uint{
	"CKC_X_509":           0x00000000,
	"CKC_X_509_ATTR_CERT": 0x00000001,
	"CKC_WTLS":            0x00000002,
}

// CertTypeIDToName is the reverse mapping.
var CertTypeIDToName map[uint]string

func init() {
	CertTypeIDToName = make(map[uint]string, len(CertTypeNameToID))
	for name, id := range CertTypeNameToID {
		CertTypeIDToName[id] = name
	}
}
