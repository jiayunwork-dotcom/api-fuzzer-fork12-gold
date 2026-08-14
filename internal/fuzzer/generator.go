package fuzzer

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"

	"github.com/api-fuzzer/apifuzzer/internal/core"
)

type Generator struct {
	rand   *rand.Rand
	config core.FuzzConfig
}

type GeneratedValue struct {
	Value       interface{}
	Description string
	Variant     string
}

func NewGenerator(seed int64, config core.FuzzConfig) *Generator {
	return &Generator{
		rand:   rand.New(rand.NewSource(seed)),
		config: config,
	}
}

func (g *Generator) SetSeed(seed int64) {
	g.rand = rand.New(rand.NewSource(seed))
}

func (g *Generator) GenerateForSchema(schema *core.Schema) []GeneratedValue {
	if schema == nil {
		return g.generateForString(nil)
	}

	schemaType := core.GetSchemaType(schema)

	if customPayloads, ok := g.config.CustomPayloads[schemaType]; ok && len(customPayloads) > 0 {
		var values []GeneratedValue
		for i, p := range customPayloads {
			values = append(values, GeneratedValue{
				Value:       p,
				Description: fmt.Sprintf("custom payload %d", i+1),
				Variant:     fmt.Sprintf("custom_%d", i+1),
			})
		}
		return values
	}

	switch schemaType {
	case "integer", "number":
		return g.generateForNumber(schema)
	case "string":
		return g.generateForString(schema)
	case "boolean":
		return g.generateForBoolean(schema)
	case "array":
		return g.generateForArray(schema)
	case "object":
		return g.generateForObject(schema)
	default:
		return g.generateForString(schema)
	}
}

func (g *Generator) generateForNumber(schema *core.Schema) []GeneratedValue {
	var values []GeneratedValue

	if g.config.GenerateBoundary {
		values = append(values, GeneratedValue{Value: 0, Description: "zero", Variant: "zero"})
		values = append(values, GeneratedValue{Value: 1, Description: "one", Variant: "one"})
		values = append(values, GeneratedValue{Value: -1, Description: "negative_one", Variant: "negative_one"})
		values = append(values, GeneratedValue{Value: math.MaxInt32, Description: "max_int32", Variant: "max_int32"})
		values = append(values, GeneratedValue{Value: math.MinInt32, Description: "min_int32", Variant: "min_int32"})
		values = append(values, GeneratedValue{Value: math.MaxInt64, Description: "overflow_max_int64", Variant: "overflow_max"})
		values = append(values, GeneratedValue{Value: math.MinInt64, Description: "overflow_min_int64", Variant: "overflow_min"})
		values = append(values, GeneratedValue{Value: 3.14159, Description: "float_value", Variant: "float"})
		values = append(values, GeneratedValue{Value: -2.71828, Description: "negative_float", Variant: "negative_float"})

		if schema != nil {
			if schema.Minimum != nil {
				minVal := *schema.Minimum
				if schema.ExclusiveMinimum {
					values = append(values, GeneratedValue{
						Value:       minVal,
						Description: "below_exclusive_minimum",
						Variant:     "below_exclusive_min",
					})
					values = append(values, GeneratedValue{
						Value:       minVal + 1,
						Description: "just_above_minimum",
						Variant:     "just_above_min",
					})
				} else {
					values = append(values, GeneratedValue{
						Value:       minVal,
						Description: "at_minimum",
						Variant:     "at_min",
					})
					values = append(values, GeneratedValue{
						Value:       minVal - 1,
						Description: "below_minimum",
						Variant:     "below_min",
					})
				}
			}
			if schema.Maximum != nil {
				maxVal := *schema.Maximum
				if schema.ExclusiveMaximum {
					values = append(values, GeneratedValue{
						Value:       maxVal,
						Description: "at_exclusive_maximum",
						Variant:     "at_exclusive_max",
					})
					values = append(values, GeneratedValue{
						Value:       maxVal - 1,
						Description: "just_below_maximum",
						Variant:     "just_below_max",
					})
				} else {
					values = append(values, GeneratedValue{
						Value:       maxVal,
						Description: "at_maximum",
						Variant:     "at_max",
					})
					values = append(values, GeneratedValue{
						Value:       maxVal + 1,
						Description: "above_maximum",
						Variant:     "above_max",
					})
				}
			}
		}
	}

	if g.config.GenerateMalicious {
		values = append(values, GeneratedValue{Value: "not_a_number", Description: "string_instead_of_number", Variant: "type_error_string"})
		values = append(values, GeneratedValue{Value: true, Description: "bool_instead_of_number", Variant: "type_error_bool"})
	}

	if len(schema.Enum) > 0 {
		for _, e := range schema.Enum {
			values = append(values, GeneratedValue{
				Value:       e,
				Description: fmt.Sprintf("enum_value_%v", e),
				Variant:     "enum_valid",
			})
		}
		if g.config.GenerateBoundary {
			values = append(values, GeneratedValue{
				Value:       "not_in_enum",
				Description: "value_not_in_enum",
				Variant:     "enum_invalid",
			})
		}
	}

	if schema != nil && schema.Nullable {
		values = append(values, GeneratedValue{Value: nil, Description: "null_value", Variant: "null"})
	}

	return values
}

func (g *Generator) generateForString(schema *core.Schema) []GeneratedValue {
	var values []GeneratedValue

	if g.config.GenerateBoundary {
		values = append(values, GeneratedValue{Value: "", Description: "empty_string", Variant: "empty"})
		values = append(values, GeneratedValue{Value: "a", Description: "single_char", Variant: "single_char"})
		values = append(values, GeneratedValue{
			Value:       strings.Repeat("A", 10000),
			Description: "long_string_10000_chars",
			Variant:     "long_string",
		})

		specialChars := []string{
			"\n", "\t", "\r", "\x00", "\x1b",
			"!@#$%^&*()_+-=[]{}|;':\",./<>?",
			"你好世界", "🌍🔥",
		}
		for i, sc := range specialChars {
			values = append(values, GeneratedValue{
				Value:       sc,
				Description: fmt.Sprintf("special_chars_%d", i),
				Variant:     fmt.Sprintf("special_%d", i),
			})
		}
	}

	if g.config.GenerateMalicious {
		sqlInjections := []string{
			"' OR 1=1--",
			"' UNION SELECT NULL,NULL,NULL--",
			"1; DROP TABLE users--",
			"' OR '1'='1",
			"admin' --",
		}
		for i, payload := range sqlInjections {
			values = append(values, GeneratedValue{
				Value:       payload,
				Description: fmt.Sprintf("sql_injection_%d", i+1),
				Variant:     fmt.Sprintf("sqli_%d", i+1),
			})
		}

		xssPayloads := []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"\"><script>alert('xss')</script>",
			"javascript:alert(1)",
		}
		for i, payload := range xssPayloads {
			values = append(values, GeneratedValue{
				Value:       payload,
				Description: fmt.Sprintf("xss_payload_%d", i+1),
				Variant:     fmt.Sprintf("xss_%d", i+1),
			})
		}

		pathTraversal := []string{
			"../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"/etc/passwd",
			"../../../../../../etc/hosts",
		}
		for i, payload := range pathTraversal {
			values = append(values, GeneratedValue{
				Value:       payload,
				Description: fmt.Sprintf("path_traversal_%d", i+1),
				Variant:     fmt.Sprintf("path_traversal_%d", i+1),
			})
		}

		formatString := "%s%s%s%n%x%x%x"
		values = append(values, GeneratedValue{
			Value:       formatString,
			Description: "format_string_attack",
			Variant:     "format_string",
		})
	}

	if schema != nil {
		if schema.MinLength != nil && g.config.GenerateBoundary {
			minLen := *schema.MinLength
			if minLen > 0 {
				values = append(values, GeneratedValue{
					Value:       strings.Repeat("a", int(minLen)-1),
					Description: fmt.Sprintf("below_min_length_%d", minLen),
					Variant:     "below_min_length",
				})
			}
			values = append(values, GeneratedValue{
				Value:       strings.Repeat("a", int(minLen)),
				Description: fmt.Sprintf("at_min_length_%d", minLen),
				Variant:     "at_min_length",
			})
		}
		if schema.MaxLength != nil && g.config.GenerateBoundary {
			maxLen := *schema.MaxLength
			values = append(values, GeneratedValue{
				Value:       strings.Repeat("a", int(maxLen)),
				Description: fmt.Sprintf("at_max_length_%d", maxLen),
				Variant:     "at_max_length",
			})
			values = append(values, GeneratedValue{
				Value:       strings.Repeat("a", int(maxLen)+1),
				Description: fmt.Sprintf("above_max_length_%d", maxLen+1),
				Variant:     "above_max_length",
			})
		}
		if schema.Pattern != "" && g.config.GenerateMalicious {
			values = append(values, GeneratedValue{
				Value:       "!!!not_matching_pattern!!!",
				Description: "string_not_matching_pattern",
				Variant:     "pattern_violation",
			})
		}
		if schema.Format == "date" || schema.Format == "date-time" {
			values = append(values, GeneratedValue{
				Value:       "0000-01-01",
				Description: "min_date",
				Variant:     "date_min",
			})
			values = append(values, GeneratedValue{
				Value:       "9999-12-31",
				Description: "max_date",
				Variant:     "date_max",
			})
			values = append(values, GeneratedValue{
				Value:       "not-a-date",
				Description: "invalid_date_format",
				Variant:     "date_invalid",
			})
			values = append(values, GeneratedValue{
				Value:       "2024-12-31T23:59:59-12:00",
				Description: "timezone_boundary",
				Variant:     "date_tz_boundary",
			})
		}
	}

	if len(schema.Enum) > 0 {
		for _, e := range schema.Enum {
			values = append(values, GeneratedValue{
				Value:       e,
				Description: fmt.Sprintf("enum_value_%v", e),
				Variant:     "enum_valid",
			})
		}
		if g.config.GenerateBoundary {
			values = append(values, GeneratedValue{
				Value:       "not_in_enum",
				Description: "value_not_in_enum",
				Variant:     "enum_invalid",
			})
		}
	}

	if schema != nil && schema.Nullable {
		values = append(values, GeneratedValue{Value: nil, Description: "null_value", Variant: "null"})
	}

	return values
}

func (g *Generator) generateForBoolean(schema *core.Schema) []GeneratedValue {
	var values []GeneratedValue

	values = append(values, GeneratedValue{Value: true, Description: "true", Variant: "true"})
	values = append(values, GeneratedValue{Value: false, Description: "false", Variant: "false"})

	if g.config.GenerateBoundary {
		values = append(values, GeneratedValue{Value: nil, Description: "null", Variant: "null"})
		values = append(values, GeneratedValue{Value: 0, Description: "zero_as_bool", Variant: "int_zero"})
		values = append(values, GeneratedValue{Value: 1, Description: "one_as_bool", Variant: "int_one"})
		values = append(values, GeneratedValue{Value: "true", Description: "string_true", Variant: "string_true"})
		values = append(values, GeneratedValue{Value: "false", Description: "string_false", Variant: "string_false"})
		values = append(values, GeneratedValue{Value: "yes", Description: "string_yes", Variant: "string_yes"})
		values = append(values, GeneratedValue{Value: "", Description: "empty_string", Variant: "empty_string"})
	}

	if schema != nil && schema.Nullable {
		values = append(values, GeneratedValue{Value: nil, Description: "null_value", Variant: "null_explicit"})
	}

	return values
}

func (g *Generator) generateForArray(schema *core.Schema) []GeneratedValue {
	var values []GeneratedValue
	itemSchema := schema.Items
	if itemSchema == nil {
		itemSchema = &core.Schema{Type: "string"}
	}

	sampleItem := g.GenerateForSchema(itemSchema)
	var validItem interface{}
	if len(sampleItem) > 0 {
		validItem = sampleItem[0].Value
	} else {
		validItem = "test"
	}

	if g.config.GenerateBoundary {
		values = append(values, GeneratedValue{
			Value:       []interface{}{},
			Description: "empty_array",
			Variant:     "empty",
		})
		values = append(values, GeneratedValue{
			Value:       []interface{}{validItem},
			Description: "single_element",
			Variant:     "single",
		})

		largeArray := make([]interface{}, 10000)
		for i := 0; i < 10000; i++ {
			largeArray[i] = validItem
		}
		values = append(values, GeneratedValue{
			Value:       largeArray,
			Description: "large_array_10000_elements",
			Variant:     "large",
		})

		values = append(values, GeneratedValue{
			Value:       []interface{}{[]interface{}{validItem}},
			Description: "nested_array",
			Variant:     "nested",
		})
	}

	if g.config.GenerateMalicious {
		values = append(values, GeneratedValue{
			Value:       "not_an_array",
			Description: "string_instead_of_array",
			Variant:     "type_error_string",
		})
		values = append(values, GeneratedValue{
			Value:       map[string]interface{}{"key": "value"},
			Description: "object_instead_of_array",
			Variant:     "type_error_object",
		})
	}

	if schema.MinItems != nil && g.config.GenerateBoundary {
		minItems := *schema.MinItems
		if minItems > 0 {
			belowMin := make([]interface{}, int(minItems)-1)
			for i := range belowMin {
				belowMin[i] = validItem
			}
			values = append(values, GeneratedValue{
				Value:       belowMin,
				Description: fmt.Sprintf("below_min_items_%d", minItems),
				Variant:     "below_min_items",
			})
		}
		atMin := make([]interface{}, int(minItems))
		for i := range atMin {
			atMin[i] = validItem
		}
		values = append(values, GeneratedValue{
			Value:       atMin,
			Description: fmt.Sprintf("at_min_items_%d", minItems),
			Variant:     "at_min_items",
		})
	}
	if schema.MaxItems != nil && g.config.GenerateBoundary {
		maxItems := *schema.MaxItems
		atMax := make([]interface{}, int(maxItems))
		for i := range atMax {
			atMax[i] = validItem
		}
		values = append(values, GeneratedValue{
			Value:       atMax,
			Description: fmt.Sprintf("at_max_items_%d", maxItems),
			Variant:     "at_max_items",
		})

		aboveMax := make([]interface{}, int(maxItems)+1)
		for i := range aboveMax {
			aboveMax[i] = validItem
		}
		values = append(values, GeneratedValue{
			Value:       aboveMax,
			Description: fmt.Sprintf("above_max_items_%d", maxItems+1),
			Variant:     "above_max_items",
		})
	}

	if schema.Nullable {
		values = append(values, GeneratedValue{Value: nil, Description: "null_array", Variant: "null"})
	}

	return values
}

func (g *Generator) generateForObject(schema *core.Schema) []GeneratedValue {
	var values []GeneratedValue

	if g.config.GenerateBoundary {
		values = append(values, GeneratedValue{
			Value:       map[string]interface{}{},
			Description: "empty_object",
			Variant:     "empty",
		})
	}

	if schema.Properties != nil && len(schema.Properties) > 0 {
		validObj := g.generateValidObject(schema)
		values = append(values, GeneratedValue{
			Value:       validObj,
			Description: "valid_object",
			Variant:     "valid",
		})

		if g.config.GenerateBoundary {
			if len(schema.Required) > 0 {
				missingRequired := make(map[string]interface{})
				for k, v := range validObj {
					if !core.ContainsString(schema.Required, k) {
						missingRequired[k] = v
					}
				}
				values = append(values, GeneratedValue{
					Value:       missingRequired,
					Description: "missing_required_fields",
					Variant:     "missing_required",
				})
			}

			extraFields := make(map[string]interface{})
			for k, v := range validObj {
				extraFields[k] = v
			}
			extraFields["__unknown_field__"] = "malicious_value"
			extraFields["another_unknown"] = 12345
			values = append(values, GeneratedValue{
				Value:       extraFields,
				Description: "extra_unknown_fields",
				Variant:     "extra_fields",
			})

			if len(schema.Properties) > 0 {
				for fieldName, fieldSchema := range schema.Properties {
					wrongType := make(map[string]interface{})
					for k, v := range validObj {
						wrongType[k] = v
					}
					wrongType[fieldName] = g.getWrongTypeValue(fieldSchema)
					values = append(values, GeneratedValue{
						Value:       wrongType,
						Description: fmt.Sprintf("wrong_type_for_field_%s", fieldName),
						Variant:     fmt.Sprintf("wrong_type_%s", fieldName),
					})
				}
			}
		}

		if g.config.GenerateBoundary {
			deepNested := g.generateDeepObject(g.config.MaxDepth)
			values = append(values, GeneratedValue{
				Value:       deepNested,
				Description: fmt.Sprintf("deeply_nested_object_%d_levels", g.config.MaxDepth),
				Variant:     "deep_nested",
			})
		}
	}

	if g.config.GenerateMalicious {
		values = append(values, GeneratedValue{
			Value:       "not_an_object",
			Description: "string_instead_of_object",
			Variant:     "type_error_string",
		})
		values = append(values, GeneratedValue{
			Value:       []interface{}{"not", "an", "object"},
			Description: "array_instead_of_object",
			Variant:     "type_error_array",
		})
	}

	if schema.Nullable {
		values = append(values, GeneratedValue{Value: nil, Description: "null_object", Variant: "null"})
	}

	return values
}

func (g *Generator) generateValidObject(schema *core.Schema) map[string]interface{} {
	obj := make(map[string]interface{})
	for fieldName, fieldSchema := range schema.Properties {
		fieldValues := g.GenerateForSchema(fieldSchema)
		if len(fieldValues) > 0 {
			obj[fieldName] = fieldValues[0].Value
		}
	}
	return obj
}

func (g *Generator) getWrongTypeValue(schema *core.Schema) interface{} {
	schemaType := core.GetSchemaType(schema)
	switch schemaType {
	case "string":
		return 12345
	case "integer", "number":
		return "not_a_number"
	case "boolean":
		return "not_a_bool"
	case "array":
		return "not_an_array"
	case "object":
		return "not_an_object"
	default:
		return 99999
	}
}

func (g *Generator) generateDeepObject(depth int) map[string]interface{} {
	if depth <= 0 {
		return map[string]interface{}{"leaf": "value"}
	}
	return map[string]interface{}{
		"nested": g.generateDeepObject(depth - 1),
	}
}

func (g *Generator) GenerateForFileUpload() []GeneratedValue {
	var values []GeneratedValue

	values = append(values, GeneratedValue{
		Value:       []byte{},
		Description: "empty_file",
		Variant:     "empty",
	})

	largeFile := make([]byte, 10*1024*1024)
	for i := range largeFile {
		largeFile[i] = byte(i % 256)
	}
	values = append(values, GeneratedValue{
		Value:       largeFile,
		Description: "large_file_10MB",
		Variant:     "large",
	})

	if g.config.GenerateMalicious {
		values = append(values, GeneratedValue{
			Value:       map[string]interface{}{"filename": "../../etc/passwd", "content": []byte("malicious")},
			Description: "path_traversal_filename",
			Variant:     "path_traversal",
		})
		values = append(values, GeneratedValue{
			Value:       map[string]interface{}{"filename": "shell.php", "content": []byte("<?php phpinfo(); ?>"), "content_type": "image/png"},
			Description: "wrong_mime_type",
			Variant:     "wrong_mime",
		})
	}

	return values
}

func (g *Generator) GenerateTestCases(api *core.API, targetURL string, config core.FuzzConfig) ([]*core.TestCase, error) {
	var testCases []*core.TestCase
	var totalGenerated int

	for path, methods := range api.Paths {
		if core.ContainsString(config.ExcludeEndpoints, path) {
			continue
		}

		if config.Stateful {
			_ = getResourceTypeFromPath(path)
		}

		for method, operation := range methods {
			if operation.Deprecated {
				continue
			}

			endpointKey := fmt.Sprintf("%s %s", method, path)

			paramValues := make(map[string][]GeneratedValue)

			for _, param := range operation.Parameters {
				if core.ContainsString(config.ExcludeParams, param.Name) {
					continue
				}
				values := g.GenerateForSchema(param.Schema)
				if len(values) > 0 {
					paramValues[param.Name] = values
				}
			}

			var bodyValues []GeneratedValue
			var contentType string
			if operation.RequestBody != nil {
				for ct, mediaType := range operation.RequestBody.Content {
					if strings.Contains(ct, "multipart/form-data") || strings.Contains(ct, "application/x-www-form-urlencoded") {
						bodyValues = g.GenerateForFileUpload()
					} else if mediaType.Schema != nil {
						bodyValues = g.GenerateForSchema(mediaType.Schema)
					}
					contentType = ct
					break
				}
			}

			combinations := g.generateCombinations(paramValues, bodyValues)

			for i, combo := range combinations {
				if totalGenerated >= config.MaxTestCases {
					break
				}

				tc := &core.TestCase{
					ID:           core.GenerateID(),
					Seed:         config.Seed + int64(totalGenerated),
					Operation:    operation,
					PathParams:   make(map[string]interface{}),
					QueryParams:  make(map[string]interface{}),
					HeaderParams: make(map[string]interface{}),
					CookieParams: make(map[string]interface{}),
					ContentType:  contentType,
					Description:  fmt.Sprintf("%s - test case %d", endpointKey, i+1),
					IsStateful:   config.Stateful,
				}

				for _, param := range operation.Parameters {
					if val, ok := combo.Params[param.Name]; ok {
						switch param.Location {
						case core.ParamLocationPath:
							tc.PathParams[param.Name] = val
						case core.ParamLocationQuery:
							tc.QueryParams[param.Name] = val
						case core.ParamLocationHeader:
							tc.HeaderParams[param.Name] = val
						case core.ParamLocationCookie:
							tc.CookieParams[param.Name] = val
						}
					}
				}

				if combo.Body != nil {
					tc.Body = combo.Body
				}

				testCases = append(testCases, tc)
				totalGenerated++
			}

			if totalGenerated >= config.MaxTestCases {
				break
			}
		}

		if totalGenerated >= config.MaxTestCases {
			break
		}
	}

	return testCases, nil
}

type valueCombination struct {
	Params map[string]interface{}
	Body   interface{}
}

func (g *Generator) generateCombinations(paramValues map[string][]GeneratedValue, bodyValues []GeneratedValue) []valueCombination {
	var combinations []valueCombination

	paramNames := make([]string, 0, len(paramValues))
	for name := range paramValues {
		paramNames = append(paramNames, name)
	}

	if len(paramNames) == 0 && len(bodyValues) == 0 {
		return []valueCombination{{Params: make(map[string]interface{})}}
	}

	maxVariants := 5
	for i := 0; i < maxVariants; i++ {
		combo := valueCombination{
			Params: make(map[string]interface{}),
		}

		for _, name := range paramNames {
			values := paramValues[name]
			if len(values) > 0 {
				idx := i % len(values)
				combo.Params[name] = values[idx].Value
			}
		}

		if len(bodyValues) > 0 {
			idx := i % len(bodyValues)
			combo.Body = bodyValues[idx].Value
		}

		combinations = append(combinations, combo)
	}

	for _, name := range paramNames {
		values := paramValues[name]
		for _, val := range values {
			combo := valueCombination{
				Params: make(map[string]interface{}),
			}
			combo.Params[name] = val.Value
			for _, otherName := range paramNames {
				if otherName != name {
					otherValues := paramValues[otherName]
					if len(otherValues) > 0 {
						combo.Params[otherName] = otherValues[0].Value
					}
				}
			}
			combinations = append(combinations, combo)
		}
	}

	return combinations
}

func (g *Generator) GenerateValueWithVariant(schema *core.Schema, variant string) (interface{}, string) {
	values := g.GenerateForSchema(schema)
	for _, v := range values {
		if v.Variant == variant {
			return v.Value, v.Description
		}
	}
	if len(values) > 0 {
		return values[0].Value, values[0].Description
	}
	return nil, "default"
}

func BuildURL(baseURL, path string, pathParams map[string]interface{}, queryParams map[string]interface{}) string {
	url := baseURL
	if !strings.HasSuffix(url, "/") && !strings.HasPrefix(path, "/") {
		url += "/"
	}
	url += path

	for name, value := range pathParams {
		placeholder := "{" + name + "}"
		url = strings.ReplaceAll(url, placeholder, core.ToString(value))
	}

	if len(queryParams) > 0 {
		queryString := core.MapToQueryString(queryParams)
		if strings.Contains(url, "?") {
			url += "&" + queryString
		} else {
			url += "?" + queryString
		}
	}

	return url
}

func MarshalBody(body interface{}) (string, error) {
	if body == nil {
		return "", nil
	}
	switch b := body.(type) {
	case string:
		return b, nil
	case []byte:
		return string(b), nil
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func getResourceTypeFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if !strings.HasPrefix(part, "{") && !strings.HasSuffix(part, "}") {
			return part
		}
	}
	return ""
}
