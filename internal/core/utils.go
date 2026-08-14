package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strconv"
	"strings"
)

func GenerateID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", math.MaxInt64)
	}
	return hex.EncodeToString(b)
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func GenerateRandomInt(min, max int64) int64 {
	if min > max {
		min, max = max, min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(max-min+1))
	return n.Int64() + min
}

func GenerateRandomFloat(min, max float64) float64 {
	if min > max {
		min, max = max, min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return min + (float64(n.Int64())/float64(math.MaxInt64))*(max-min)
}

func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func ToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case []byte:
		return string(val)
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("%v", val)
		}
		return string(b)
	}
}

func ToInt(v interface{}) (int64, error) {
	switch val := v.(type) {
	case int:
		return int64(val), nil
	case int64:
		return val, nil
	case float64:
		return int64(val), nil
	case string:
		return strconv.ParseInt(val, 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}

func ToFloat(v interface{}) (float64, error) {
	switch val := v.(type) {
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case float64:
		return val, nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

func MapToQueryString(params map[string]interface{}) string {
	if len(params) == 0 {
		return ""
	}
	var parts []string
	for k, v := range params {
		key := url.QueryEscape(k)
		value := url.QueryEscape(ToString(v))
		parts = append(parts, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(parts, "&")
}

func TruncateString(s string, maxLength int) string {
	if len(s) < maxLength {
		return s
	}
	if maxLength <= 0 {
		return ""
	}
	return s[:maxLength-1]
}

func TruncateBytes(b []byte, maxBytes int64) ([]byte, bool) {
	if int64(len(b)) <= maxBytes {
		return b, false
	}
	return b[:maxBytes], true
}

func DeepCopySchema(s *Schema) *Schema {
	if s == nil {
		return nil
	}
	copy := &Schema{
		Type:             s.Type,
		Format:           s.Format,
		Required:         append([]string{}, s.Required...),
		Enum:             append([]interface{}{}, s.Enum...),
		Pattern:          s.Pattern,
		Nullable:         s.Nullable,
		Description:      s.Description,
		Ref:              s.Ref,
		ExclusiveMinimum: s.ExclusiveMinimum,
		ExclusiveMaximum: s.ExclusiveMaximum,
		Default:          s.Default,
	}
	if s.MinLength != nil {
		v := *s.MinLength
		copy.MinLength = &v
	}
	if s.MaxLength != nil {
		v := *s.MaxLength
		copy.MaxLength = &v
	}
	if s.Minimum != nil {
		v := *s.Minimum
		copy.Minimum = &v
	}
	if s.Maximum != nil {
		v := *s.Maximum
		copy.Maximum = &v
	}
	if s.MinItems != nil {
		v := *s.MinItems
		copy.MinItems = &v
	}
	if s.MaxItems != nil {
		v := *s.MaxItems
		copy.MaxItems = &v
	}
	if s.MinProperties != nil {
		v := *s.MinProperties
		copy.MinProperties = &v
	}
	if s.MaxProperties != nil {
		v := *s.MaxProperties
		copy.MaxProperties = &v
	}
	if s.Items != nil {
		copy.Items = DeepCopySchema(s.Items)
	}
	if s.Properties != nil {
		copy.Properties = make(map[string]*Schema)
		for k, v := range s.Properties {
			copy.Properties[k] = DeepCopySchema(v)
		}
	}
	if s.AdditionalProperties != nil {
		copy.AdditionalProperties = DeepCopySchema(s.AdditionalProperties)
	}
	return copy
}

func GetSchemaType(s *Schema) string {
	if s == nil {
		return ""
	}
	if s.Type != "" {
		return s.Type
	}
	if len(s.Enum) > 0 {
		return "string"
	}
	if s.Properties != nil {
		return "object"
	}
	if s.Items != nil {
		return "array"
	}
	return "string"
}
