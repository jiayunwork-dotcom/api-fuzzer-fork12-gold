package openapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"gopkg.in/yaml.v3"
)

type ParseError struct {
	Path    string
	Line    int
	Column  int
	Message string
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("parse error at %s (line %d, column %d): %s", e.Path, e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("parse error at %s: %s", e.Path, e.Message)
}

type Parser struct {
	specPath  string
	basePath  string
	refCache  map[string]interface{}
	rawSpec   map[string]interface{}
}

func NewParser(specPath string) *Parser {
	return &Parser{
		specPath: specPath,
		refCache: make(map[string]interface{}),
	}
}

func (p *Parser) Parse() (*core.API, error) {
	data, err := os.ReadFile(p.specPath)
	if err != nil {
		return nil, &ParseError{Path: p.specPath, Message: fmt.Sprintf("failed to read file: %v", err)}
	}

	p.basePath = filepath.Dir(p.specPath)

	var raw map[string]interface{}
	if strings.HasSuffix(strings.ToLower(p.specPath), ".json") {
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, p.createParseError(err, data)
		}
	} else {
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return nil, p.createParseError(err, data)
		}
		if len(node.Content) > 0 {
			raw = p.yamlNodeToMap(node.Content[0])
		}
	}

	if raw == nil {
		return nil, &ParseError{Path: p.specPath, Message: "empty or invalid specification"}
	}

	p.rawSpec = raw

	openapiVersion, ok := raw["openapi"].(string)
	if !ok {
		return nil, &ParseError{Path: p.specPath, Message: "missing or invalid 'openapi' version field"}
	}
	if !strings.HasPrefix(openapiVersion, "3.0") && !strings.HasPrefix(openapiVersion, "3.1") {
		return nil, &ParseError{Path: p.specPath, Message: fmt.Sprintf("unsupported OpenAPI version: %s (only 3.0/3.1 supported)", openapiVersion)}
	}

	api := &core.API{
		Version: openapiVersion,
		Paths:   make(map[string]map[string]*core.Operation),
	}

	if info, ok := raw["info"].(map[string]interface{}); ok {
		if title, ok := info["title"].(string); ok {
			api.Title = title
		}
		if desc, ok := info["description"].(string); ok {
			api.Description = desc
		}
	}

	if servers, ok := raw["servers"].([]interface{}); ok {
		for _, s := range servers {
			if serverMap, ok := s.(map[string]interface{}); ok {
				server := core.Server{}
				if u, ok := serverMap["url"].(string); ok {
					server.URL = u
				}
				if d, ok := serverMap["description"].(string); ok {
					server.Description = d
				}
				if vars, ok := serverMap["variables"].(map[string]interface{}); ok {
					server.Variables = make(map[string]*core.ServerVariable)
					for k, v := range vars {
						if varMap, ok := v.(map[string]interface{}); ok {
							sv := &core.ServerVariable{}
							if en, ok := varMap["enum"].([]interface{}); ok {
								for _, e := range en {
									if es, ok := e.(string); ok {
										sv.Enum = append(sv.Enum, es)
									}
								}
							}
							if def, ok := varMap["default"].(string); ok {
								sv.Default = def
							}
							if desc, ok := varMap["description"].(string); ok {
								sv.Description = desc
							}
							server.Variables[k] = sv
						}
					}
				}
				api.Servers = append(api.Servers, server)
			}
		}
	}

	if security, ok := raw["security"].([]interface{}); ok {
		api.Security = p.parseSecurityRequirements(security)
	}

	if components, ok := raw["components"].(map[string]interface{}); ok {
		api.Components = p.parseComponents(components)
	}

	if paths, ok := raw["paths"].(map[string]interface{}); ok {
		for path, pathItem := range paths {
			pathItemMap, ok := pathItem.(map[string]interface{})
			if !ok {
				continue
			}
			pathItemMap = p.resolveRefIfNeeded(pathItemMap)

			api.Paths[path] = make(map[string]*core.Operation)

			httpMethods := map[string]bool{
				"get": true, "post": true, "put": true, "delete": true,
				"patch": true, "head": true, "options": true, "trace": true,
			}

			for method, opData := range pathItemMap {
				if !httpMethods[method] {
					continue
				}
				opMap, ok := opData.(map[string]interface{})
				if !ok {
					continue
				}
				opMap = p.resolveRefIfNeeded(opMap)

				op, err := p.parseOperation(path, method, opMap)
				if err != nil {
					return nil, err
				}
				api.Paths[path][method] = op
			}

			if params, ok := pathItemMap["parameters"].([]interface{}); ok {
				for _, param := range params {
					paramMap, ok := param.(map[string]interface{})
					if !ok {
						continue
					}
					paramMap = p.resolveRefIfNeeded(paramMap)
					parsedParam := p.parseParameter(paramMap)
					if parsedParam != nil {
						for _, op := range api.Paths[path] {
							op.Parameters = append(op.Parameters, parsedParam)
						}
					}
				}
			}
		}
	}

	totalEndpoints := 0
	for _, methods := range api.Paths {
		totalEndpoints += len(methods)
	}

	return api, nil
}

func (p *Parser) parseOperation(path, method string, opMap map[string]interface{}) (*core.Operation, error) {
	op := &core.Operation{
		Method: strings.ToUpper(method),
		Path:   path,
	}

	if opID, ok := opMap["operationId"].(string); ok {
		op.OperationID = opID
	}
	if summary, ok := opMap["summary"].(string); ok {
		op.Summary = summary
	}
	if desc, ok := opMap["description"].(string); ok {
		op.Description = desc
	}
	if deprecated, ok := opMap["deprecated"].(bool); ok {
		op.Deprecated = deprecated
	}
	if tags, ok := opMap["tags"].([]interface{}); ok {
		for _, t := range tags {
			if ts, ok := t.(string); ok {
				op.Tags = append(op.Tags, ts)
			}
		}
	}

	if params, ok := opMap["parameters"].([]interface{}); ok {
		for _, param := range params {
			paramMap, ok := param.(map[string]interface{})
			if !ok {
				continue
			}
			paramMap = p.resolveRefIfNeeded(paramMap)
			parsedParam := p.parseParameter(paramMap)
			if parsedParam != nil {
				op.Parameters = append(op.Parameters, parsedParam)
			}
		}
	}

	if reqBody, ok := opMap["requestBody"].(map[string]interface{}); ok {
		reqBody = p.resolveRefIfNeeded(reqBody)
		op.RequestBody = p.parseRequestBody(reqBody)
	}

	if responses, ok := opMap["responses"].(map[string]interface{}); ok {
		op.Responses = make(map[string]*core.Response)
		for code, resp := range responses {
			respMap, ok := resp.(map[string]interface{})
			if !ok {
				continue
			}
			respMap = p.resolveRefIfNeeded(respMap)
			op.Responses[code] = p.parseResponse(respMap)
		}
	}

	if security, ok := opMap["security"].([]interface{}); ok {
		op.Security = p.parseSecurityRequirements(security)
	}

	return op, nil
}

func (p *Parser) parseParameter(paramMap map[string]interface{}) *core.Parameter {
	param := &core.Parameter{}

	if name, ok := paramMap["name"].(string); ok {
		param.Name = name
	}
	if in, ok := paramMap["in"].(string); ok {
		param.Location = core.ParameterLocation(in)
	}
	if desc, ok := paramMap["description"].(string); ok {
		param.Description = desc
	}
	if required, ok := paramMap["required"].(bool); ok {
		param.Required = required
	}
	if deprecated, ok := paramMap["deprecated"].(bool); ok {
		param.Deprecated = deprecated
	}

	if schema, ok := paramMap["schema"].(map[string]interface{}); ok {
		schema = p.resolveRefIfNeeded(schema)
		param.Schema = p.parseSchema(schema)
	}

	return param
}

func (p *Parser) parseSchema(schemaMap map[string]interface{}) *core.Schema {
	if ref, ok := schemaMap["$ref"].(string); ok {
		resolved, err := p.resolveRef(ref)
		if err != nil {
			return &core.Schema{Ref: ref}
		}
		if resolvedMap, ok := resolved.(map[string]interface{}); ok {
			s := p.parseSchema(resolvedMap)
			s.Ref = ref
			return s
		}
	}

	s := &core.Schema{}

	if t, ok := schemaMap["type"].(string); ok {
		s.Type = t
	}
	if format, ok := schemaMap["format"].(string); ok {
		s.Format = format
	}
	if desc, ok := schemaMap["description"].(string); ok {
		s.Description = desc
	}
	if nullable, ok := schemaMap["nullable"].(bool); ok {
		s.Nullable = nullable
	}

	if enum, ok := schemaMap["enum"].([]interface{}); ok {
		s.Enum = append([]interface{}{}, enum...)
	}
	if pattern, ok := schemaMap["pattern"].(string); ok {
		s.Pattern = pattern
	}

	if minLen, ok := schemaMap["minLength"]; ok {
		if val, err := toInt64(minLen); err == nil {
			s.MinLength = &val
		}
	}
	if maxLen, ok := schemaMap["maxLength"]; ok {
		if val, err := toInt64(maxLen); err == nil {
			s.MaxLength = &val
		}
	}
	if min, ok := schemaMap["minimum"]; ok {
		if val, err := toFloat64(min); err == nil {
			s.Minimum = &val
		}
	}
	if max, ok := schemaMap["maximum"]; ok {
		if val, err := toFloat64(max); err == nil {
			s.Maximum = &val
		}
	}
	if exclMin, ok := schemaMap["exclusiveMinimum"].(bool); ok {
		s.ExclusiveMinimum = exclMin
	}
	if exclMax, ok := schemaMap["exclusiveMaximum"].(bool); ok {
		s.ExclusiveMaximum = exclMax
	}
	if minItems, ok := schemaMap["minItems"]; ok {
		if val, err := toInt64(minItems); err == nil {
			s.MinItems = &val
		}
	}
	if maxItems, ok := schemaMap["maxItems"]; ok {
		if val, err := toInt64(maxItems); err == nil {
			s.MaxItems = &val
		}
	}
	if minProps, ok := schemaMap["minProperties"]; ok {
		if val, err := toInt64(minProps); err == nil {
			s.MinProperties = &val
		}
	}
	if maxProps, ok := schemaMap["maxProperties"]; ok {
		if val, err := toInt64(maxProps); err == nil {
			s.MaxProperties = &val
		}
	}

	if def, ok := schemaMap["default"]; ok {
		s.Default = def
	}

	if required, ok := schemaMap["required"].([]interface{}); ok {
		for _, r := range required {
			if rs, ok := r.(string); ok {
				s.Required = append(s.Required, rs)
			}
		}
	}

	if items, ok := schemaMap["items"].(map[string]interface{}); ok {
		items = p.resolveRefIfNeeded(items)
		s.Items = p.parseSchema(items)
	}

	if props, ok := schemaMap["properties"].(map[string]interface{}); ok {
		s.Properties = make(map[string]*core.Schema)
		for k, v := range props {
			if propMap, ok := v.(map[string]interface{}); ok {
				propMap = p.resolveRefIfNeeded(propMap)
				s.Properties[k] = p.parseSchema(propMap)
			}
		}
	}

	if addlProps, ok := schemaMap["additionalProperties"]; ok {
		switch ap := addlProps.(type) {
		case bool:
			if ap {
				s.AdditionalProperties = &core.Schema{Type: "string"}
			}
		case map[string]interface{}:
			ap = p.resolveRefIfNeeded(ap)
			s.AdditionalProperties = p.parseSchema(ap)
		}
	}

	return s
}

func (p *Parser) parseRequestBody(reqBodyMap map[string]interface{}) *core.RequestBody {
	rb := &core.RequestBody{}

	if desc, ok := reqBodyMap["description"].(string); ok {
		rb.Description = desc
	}
	if required, ok := reqBodyMap["required"].(bool); ok {
		rb.Required = required
	}
	if content, ok := reqBodyMap["content"].(map[string]interface{}); ok {
		rb.Content = make(map[string]*core.MediaType)
		for contentType, mt := range content {
			if mtMap, ok := mt.(map[string]interface{}); ok {
				mediaType := &core.MediaType{}
				if schema, ok := mtMap["schema"].(map[string]interface{}); ok {
					schema = p.resolveRefIfNeeded(schema)
					mediaType.Schema = p.parseSchema(schema)
				}
				rb.Content[contentType] = mediaType
			}
		}
	}

	return rb
}

func (p *Parser) parseResponse(respMap map[string]interface{}) *core.Response {
	r := &core.Response{}

	if desc, ok := respMap["description"].(string); ok {
		r.Description = desc
	}
	if headers, ok := respMap["headers"].(map[string]interface{}); ok {
		r.Headers = make(map[string]*core.Parameter)
		for k, v := range headers {
			if headerMap, ok := v.(map[string]interface{}); ok {
				headerMap = p.resolveRefIfNeeded(headerMap)
				header := &core.Parameter{
					Name:     k,
					Location: core.ParamLocationHeader,
				}
				if desc, ok := headerMap["description"].(string); ok {
					header.Description = desc
				}
				if schema, ok := headerMap["schema"].(map[string]interface{}); ok {
					schema = p.resolveRefIfNeeded(schema)
					header.Schema = p.parseSchema(schema)
				}
				r.Headers[k] = header
			}
		}
	}
	if content, ok := respMap["content"].(map[string]interface{}); ok {
		r.Content = make(map[string]*core.MediaType)
		for contentType, mt := range content {
			if mtMap, ok := mt.(map[string]interface{}); ok {
				mediaType := &core.MediaType{}
				if schema, ok := mtMap["schema"].(map[string]interface{}); ok {
					schema = p.resolveRefIfNeeded(schema)
					mediaType.Schema = p.parseSchema(schema)
				}
				r.Content[contentType] = mediaType
			}
		}
	}

	return r
}

func (p *Parser) parseComponents(componentsMap map[string]interface{}) *core.Components {
	c := &core.Components{}

	if schemas, ok := componentsMap["schemas"].(map[string]interface{}); ok {
		c.Schemas = make(map[string]*core.Schema)
		for k, v := range schemas {
			if schemaMap, ok := v.(map[string]interface{}); ok {
				schemaMap = p.resolveRefIfNeeded(schemaMap)
				c.Schemas[k] = p.parseSchema(schemaMap)
			}
		}
	}

	if parameters, ok := componentsMap["parameters"].(map[string]interface{}); ok {
		c.Parameters = make(map[string]*core.Parameter)
		for k, v := range parameters {
			if paramMap, ok := v.(map[string]interface{}); ok {
				paramMap = p.resolveRefIfNeeded(paramMap)
				c.Parameters[k] = p.parseParameter(paramMap)
			}
		}
	}

	if headers, ok := componentsMap["headers"].(map[string]interface{}); ok {
		c.Headers = make(map[string]*core.Parameter)
		for k, v := range headers {
			if headerMap, ok := v.(map[string]interface{}); ok {
				headerMap = p.resolveRefIfNeeded(headerMap)
				header := &core.Parameter{
					Name:     k,
					Location: core.ParamLocationHeader,
				}
				if desc, ok := headerMap["description"].(string); ok {
					header.Description = desc
				}
				if schema, ok := headerMap["schema"].(map[string]interface{}); ok {
					schema = p.resolveRefIfNeeded(schema)
					header.Schema = p.parseSchema(schema)
				}
				c.Headers[k] = header
			}
		}
	}

	if reqBodies, ok := componentsMap["requestBodies"].(map[string]interface{}); ok {
		c.RequestBodies = make(map[string]*core.RequestBody)
		for k, v := range reqBodies {
			if rbMap, ok := v.(map[string]interface{}); ok {
				rbMap = p.resolveRefIfNeeded(rbMap)
				c.RequestBodies[k] = p.parseRequestBody(rbMap)
			}
		}
	}

	if responses, ok := componentsMap["responses"].(map[string]interface{}); ok {
		c.Responses = make(map[string]*core.Response)
		for k, v := range responses {
			if respMap, ok := v.(map[string]interface{}); ok {
				respMap = p.resolveRefIfNeeded(respMap)
				c.Responses[k] = p.parseResponse(respMap)
			}
		}
	}

	if securitySchemes, ok := componentsMap["securitySchemes"].(map[string]interface{}); ok {
		c.SecuritySchemes = make(map[string]*core.SecurityScheme)
		for k, v := range securitySchemes {
			if ssMap, ok := v.(map[string]interface{}); ok {
				ssMap = p.resolveRefIfNeeded(ssMap)
				scheme := &core.SecurityScheme{}
				if t, ok := ssMap["type"].(string); ok {
					scheme.Type = t
				}
				if desc, ok := ssMap["description"].(string); ok {
					scheme.Description = desc
				}
				if name, ok := ssMap["name"].(string); ok {
					scheme.Name = name
				}
				if in, ok := ssMap["in"].(string); ok {
					scheme.In = in
				}
				if s, ok := ssMap["scheme"].(string); ok {
					scheme.Scheme = s
				}
				if bf, ok := ssMap["bearerFormat"].(string); ok {
					scheme.BearerFormat = bf
				}
				if oidc, ok := ssMap["openIdConnectUrl"].(string); ok {
					scheme.OpenIDConnectURL = oidc
				}
				if flows, ok := ssMap["flows"].(map[string]interface{}); ok {
					scheme.Flows = &core.OAuthFlows{}
					if implicit, ok := flows["implicit"].(map[string]interface{}); ok {
						scheme.Flows.Implicit = p.parseOAuthFlow(implicit)
					}
					if password, ok := flows["password"].(map[string]interface{}); ok {
						scheme.Flows.Password = p.parseOAuthFlow(password)
					}
					if cc, ok := flows["clientCredentials"].(map[string]interface{}); ok {
						scheme.Flows.ClientCredentials = p.parseOAuthFlow(cc)
					}
					if ac, ok := flows["authorizationCode"].(map[string]interface{}); ok {
						scheme.Flows.AuthorizationCode = p.parseOAuthFlow(ac)
					}
				}
				c.SecuritySchemes[k] = scheme
			}
		}
	}

	return c
}

func (p *Parser) parseOAuthFlow(flowMap map[string]interface{}) *core.OAuthFlow {
	f := &core.OAuthFlow{}
	if au, ok := flowMap["authorizationUrl"].(string); ok {
		f.AuthorizationURL = au
	}
	if tu, ok := flowMap["tokenUrl"].(string); ok {
		f.TokenURL = tu
	}
	if ru, ok := flowMap["refreshUrl"].(string); ok {
		f.RefreshURL = ru
	}
	if scopes, ok := flowMap["scopes"].(map[string]interface{}); ok {
		f.Scopes = make(map[string]string)
		for k, v := range scopes {
			if desc, ok := v.(string); ok {
				f.Scopes[k] = desc
			}
		}
	}
	return f
}

func (p *Parser) parseSecurityRequirements(sec []interface{}) []map[string][]string {
	var result []map[string][]string
	for _, req := range sec {
		if reqMap, ok := req.(map[string]interface{}); ok {
			entry := make(map[string][]string)
			for k, v := range reqMap {
				if scopes, ok := v.([]interface{}); ok {
					var scopeList []string
					for _, s := range scopes {
						if ss, ok := s.(string); ok {
							scopeList = append(scopeList, ss)
						}
					}
					entry[k] = scopeList
				}
			}
			result = append(result, entry)
		}
	}
	return result
}

func (p *Parser) resolveRefIfNeeded(m map[string]interface{}) map[string]interface{} {
	if ref, ok := m["$ref"].(string); ok && len(m) == 1 {
		resolved, err := p.resolveRef(ref)
		if err == nil {
			if resolvedMap, ok := resolved.(map[string]interface{}); ok {
				return resolvedMap
			}
		}
	}
	return m
}

func (p *Parser) resolveRef(ref string) (interface{}, error) {
	if cached, ok := p.refCache[ref]; ok {
		return cached, nil
	}

	parts := strings.SplitN(ref, "#", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid $ref format: %s", ref)
	}

	var sourceDoc map[string]interface{}
	if parts[0] == "" {
		sourceDoc = p.rawSpec
	} else {
		refURL, err := url.Parse(parts[0])
		if err != nil || refURL.Scheme == "" {
			externalPath := filepath.Join(p.basePath, parts[0])
			data, err := os.ReadFile(externalPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read external ref %s: %w", ref, err)
			}
			var externalDoc map[string]interface{}
			if strings.HasSuffix(strings.ToLower(externalPath), ".json") {
				if err := json.Unmarshal(data, &externalDoc); err != nil {
					return nil, fmt.Errorf("failed to parse external ref %s: %w", ref, err)
				}
			} else {
				var node yaml.Node
				if err := yaml.Unmarshal(data, &node); err != nil {
					return nil, fmt.Errorf("failed to parse external ref %s: %w", ref, err)
				}
				if len(node.Content) > 0 {
					externalDoc = p.yamlNodeToMap(node.Content[0])
				}
			}
			sourceDoc = externalDoc
		} else {
			return nil, fmt.Errorf("remote $ref not supported: %s", ref)
		}
	}

	jsonPointer := parts[1]
	resolved, err := p.resolveJSONPointer(sourceDoc, jsonPointer)
	if err != nil {
		return nil, err
	}

	p.refCache[ref] = resolved
	return resolved, nil
}

func (p *Parser) resolveJSONPointer(doc map[string]interface{}, pointer string) (interface{}, error) {
	if pointer == "" || pointer == "/" {
		return doc, nil
	}

	parts := strings.Split(pointer, "/")
	if parts[0] != "" {
		return nil, fmt.Errorf("invalid JSON pointer: %s", pointer)
	}

	var current interface{} = doc
	for i := 1; i < len(parts); i++ {
		segment := unescapeJSONPointer(parts[i])

		switch curr := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = curr[segment]
			if !ok {
				return nil, fmt.Errorf("JSON pointer segment not found: %s", segment)
			}
		case []interface{}:
			idx, err := strconv.Atoi(segment)
			if err != nil || idx < 0 || idx >= len(curr) {
				return nil, fmt.Errorf("invalid array index in JSON pointer: %s", segment)
			}
			current = curr[idx]
		default:
			return nil, fmt.Errorf("cannot navigate through %T at segment: %s", current, segment)
		}
	}

	return current, nil
}

func unescapeJSONPointer(s string) string {
	s = strings.ReplaceAll(s, "~1", "/")
	s = strings.ReplaceAll(s, "~0", "~")
	return s
}

func (p *Parser) yamlNodeToMap(node *yaml.Node) map[string]interface{} {
	result := make(map[string]interface{})
	if node.Kind != yaml.MappingNode {
		return result
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := p.yamlNodeToValue(node.Content[i+1])
		result[key] = value
	}
	return result
}

func (p *Parser) yamlNodeToValue(node *yaml.Node) interface{} {
	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!int":
			if v, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
				return v
			}
			return node.Value
		case "!!float":
			if v, err := strconv.ParseFloat(node.Value, 64); err == nil {
				return v
			}
			return node.Value
		case "!!bool":
			if v, err := strconv.ParseBool(node.Value); err == nil {
				return v
			}
			return node.Value
		case "!!null":
			return nil
		default:
			return node.Value
		}
	case yaml.SequenceNode:
		var seq []interface{}
		for _, item := range node.Content {
			seq = append(seq, p.yamlNodeToValue(item))
		}
		return seq
	case yaml.MappingNode:
		return p.yamlNodeToMap(node)
	case yaml.AliasNode:
		return p.yamlNodeToValue(node.Alias)
	default:
		return nil
	}
}

func (p *Parser) createParseError(err error, data []byte) *ParseError {
	msg := err.Error()
	var line, column int

	if yerr, ok := err.(*yaml.TypeError); ok {
		msg = strings.Join(yerr.Errors, "; ")
	}

	if lines := strings.Split(msg, "line "); len(lines) > 1 {
		if lineParts := strings.Split(lines[1], ":"); len(lineParts) > 0 {
			if l, err := strconv.Atoi(lineParts[0]); err == nil {
				line = l
			}
		}
	}

	return &ParseError{
		Path:    p.specPath,
		Line:    line,
		Column:  column,
		Message: msg,
	}
}

func toInt64(v interface{}) (int64, error) {
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

func toFloat64(v interface{}) (float64, error) {
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

func ParseOpenAPI(specPath string) (*core.API, error) {
	parser := NewParser(specPath)
	return parser.Parse()
}

func ExtractEndpointKey(method, path string) string {
	return fmt.Sprintf("%s %s", strings.ToUpper(method), path)
}

func GetResourceType(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if !strings.HasPrefix(part, "{") && !strings.HasSuffix(part, "}") {
			return part
		}
	}
	return ""
}

func HasPathParameters(path string) bool {
	return strings.Contains(path, "{") && strings.Contains(path, "}")
}

func GetPathParameterNames(path string) []string {
	var params []string
	parts := strings.Split(path, "{")
	for i := 1; i < len(parts); i++ {
		if idx := strings.Index(parts[i], "}"); idx > 0 {
			params = append(params, parts[i][:idx])
		}
	}
	return params
}

func CheckHealth(targetURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "api-fuzzer/1.0 health-check")
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 500 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	
	return nil
}
