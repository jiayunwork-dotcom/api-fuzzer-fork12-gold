package stateful

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"github.com/api-fuzzer/apifuzzer/internal/fuzzer"
)

type StatefulFuzzer struct {
	api             *core.API
	resourceContext *core.ResourceContext
	dependencyGraph *core.DependencyGraph
	generator       *fuzzer.Generator
	config          core.FuzzConfig
}

func NewStatefulFuzzer(api *core.API, seed int64, config core.FuzzConfig) *StatefulFuzzer {
	return &StatefulFuzzer{
		api:             api,
		resourceContext: core.NewResourceContext(),
		dependencyGraph: &core.DependencyGraph{Nodes: make(map[string]*core.DependencyNode)},
		generator:       fuzzer.NewGenerator(seed, config),
		config:          config,
	}
}

func (sf *StatefulFuzzer) BuildDependencyGraph() *core.DependencyGraph {
	operations := make(map[string]*core.Operation)
	resourceOps := make(map[string][]*core.Operation)

	for path, methods := range sf.api.Paths {
		resourceType := getResourceType(path)
		for method, op := range methods {
			key := fmt.Sprintf("%s %s", strings.ToUpper(method), path)
			operations[key] = op
			if resourceType != "" {
				resourceOps[resourceType] = append(resourceOps[resourceType], op)
			}
			sf.dependencyGraph.Nodes[key] = &core.DependencyNode{Operation: op}
		}
	}

	for resourceType, ops := range resourceOps {
		_ = resourceType
		var postOp *core.Operation
		var getOps []*core.Operation
		var putOps []*core.Operation
		var deleteOps []*core.Operation

		for _, op := range ops {
			switch op.Method {
			case "POST":
				postOp = op
			case "GET":
				if hasPathParameters(op.Path) {
					getOps = append(getOps, op)
				}
			case "PUT", "PATCH":
				putOps = append(putOps, op)
			case "DELETE":
				deleteOps = append(deleteOps, op)
			}
		}

		if postOp != nil {
			postKey := fmt.Sprintf("%s %s", postOp.Method, postOp.Path)
			postNode := sf.dependencyGraph.Nodes[postKey]

			for _, getOp := range getOps {
				getKey := fmt.Sprintf("%s %s", getOp.Method, getOp.Path)
				getNode := sf.dependencyGraph.Nodes[getKey]
				postNode.DependedBy = append(postNode.DependedBy, getNode)
				getNode.DependsOn = append(getNode.DependsOn, postNode)
			}

			for _, putOp := range putOps {
				putKey := fmt.Sprintf("%s %s", putOp.Method, putOp.Path)
				putNode := sf.dependencyGraph.Nodes[putKey]
				postNode.DependedBy = append(postNode.DependedBy, putNode)
				putNode.DependsOn = append(putNode.DependsOn, postNode)
			}

			for _, deleteOp := range deleteOps {
				deleteKey := fmt.Sprintf("%s %s", deleteOp.Method, deleteOp.Path)
				deleteNode := sf.dependencyGraph.Nodes[deleteKey]
				postNode.DependedBy = append(postNode.DependedBy, deleteNode)
				deleteNode.DependsOn = append(deleteNode.DependsOn, postNode)
			}
		}

		for _, getOp := range getOps {
			getKey := fmt.Sprintf("%s %s", getOp.Method, getOp.Path)
			getNode := sf.dependencyGraph.Nodes[getKey]

			for _, putOp := range putOps {
				putKey := fmt.Sprintf("%s %s", putOp.Method, putOp.Path)
				putNode := sf.dependencyGraph.Nodes[putKey]
				getNode.DependedBy = append(getNode.DependedBy, putNode)
				putNode.DependsOn = append(putNode.DependsOn, getNode)
			}

			for _, deleteOp := range deleteOps {
				deleteKey := fmt.Sprintf("%s %s", deleteOp.Method, deleteOp.Path)
				deleteNode := sf.dependencyGraph.Nodes[deleteKey]
				getNode.DependedBy = append(getNode.DependedBy, deleteNode)
				deleteNode.DependsOn = append(deleteNode.DependsOn, getNode)
			}
		}
	}

	return sf.dependencyGraph
}

func (sf *StatefulFuzzer) GenerateStatefulTestCases() []*core.TestCase {
	var testCases []*core.TestCase

	sf.BuildDependencyGraph()

	for resourceType, ops := range sf.getResourceOperations() {
		var postOp *core.Operation
		var getOp *core.Operation
		var putOp *core.Operation
		var deleteOp *core.Operation

		for _, op := range ops {
			switch op.Method {
			case "POST":
				if postOp == nil {
					postOp = op
				}
			case "GET":
				if getOp == nil && hasPathParameters(op.Path) {
					getOp = op
				}
			case "PUT":
				if putOp == nil {
					putOp = op
				}
			case "DELETE":
				if deleteOp == nil {
					deleteOp = op
				}
			}
		}

		chainID := core.GenerateID()

		if postOp != nil {
			tc := sf.createTestCase(postOp, "")
			tc.IsStateful = true
			tc.Description = fmt.Sprintf("[Stateful] Create %s (CRUD chain %s)", resourceType, chainID)
			testCases = append(testCases, tc)
		}

		if getOp != nil {
			tc := sf.createTestCase(getOp, resourceType)
			tc.IsStateful = true
			tc.Description = fmt.Sprintf("[Stateful] Get %s (CRUD chain %s)", resourceType, chainID)
			tc.DependsOn = []string{chainID + "_post"}
			testCases = append(testCases, tc)
		}

		if putOp != nil {
			tc := sf.createTestCase(putOp, resourceType)
			tc.IsStateful = true
			tc.Description = fmt.Sprintf("[Stateful] Update %s (CRUD chain %s)", resourceType, chainID)
			tc.DependsOn = []string{chainID + "_post"}
			testCases = append(testCases, tc)
		}

		if deleteOp != nil {
			tc := sf.createTestCase(deleteOp, resourceType)
			tc.IsStateful = true
			tc.Description = fmt.Sprintf("[Stateful] Delete %s (CRUD chain %s)", resourceType, chainID)
			tc.DependsOn = []string{chainID + "_post"}
			testCases = append(testCases, tc)
		}

		if postOp != nil && getOp != nil {
			tc := sf.createTestCase(getOp, "non_existent_"+resourceType)
			tc.IsStateful = true
			tc.Description = fmt.Sprintf("[Stateful] Get non-existent %s (negative test)", resourceType)
			testCases = append(testCases, tc)
		}

		if deleteOp != nil {
			tc := sf.createTestCase(deleteOp, "already_deleted_"+resourceType)
			tc.IsStateful = true
			tc.Description = fmt.Sprintf("[Stateful] Delete already deleted %s (negative test)", resourceType)
			testCases = append(testCases, tc)
		}
	}

	return testCases
}

func (sf *StatefulFuzzer) createTestCase(op *core.Operation, resourceType string) *core.TestCase {
	tc := &core.TestCase{
		ID:           core.GenerateID(),
		Seed:         sf.config.Seed,
		Operation:    op,
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]interface{}),
		HeaderParams: make(map[string]interface{}),
		CookieParams: make(map[string]interface{}),
		IsStateful:   true,
	}

	for _, param := range op.Parameters {
		if core.ContainsString(sf.config.ExcludeParams, param.Name) {
			continue
		}

		if param.Location == core.ParamLocationPath && resourceType != "" &&
			!strings.HasPrefix(resourceType, "non_existent_") &&
			!strings.HasPrefix(resourceType, "already_deleted_") {
			tc.PathParams[param.Name] = fmt.Sprintf("{{resource_id:%s}}", resourceType)
		} else {
			values := sf.generator.GenerateForSchema(param.Schema)
			if len(values) > 0 {
				switch param.Location {
				case core.ParamLocationPath:
					if strings.HasPrefix(resourceType, "non_existent_") {
						tc.PathParams[param.Name] = "non-existent-id-12345"
					} else if strings.HasPrefix(resourceType, "already_deleted_") {
						tc.PathParams[param.Name] = "already-deleted-id-12345"
					} else {
						tc.PathParams[param.Name] = values[0].Value
					}
				case core.ParamLocationQuery:
					tc.QueryParams[param.Name] = values[0].Value
				case core.ParamLocationHeader:
					tc.HeaderParams[param.Name] = values[0].Value
				case core.ParamLocationCookie:
					tc.CookieParams[param.Name] = values[0].Value
				}
			}
		}
	}

	if op.RequestBody != nil {
		for ct, mediaType := range op.RequestBody.Content {
			if mediaType.Schema != nil {
				values := sf.generator.GenerateForSchema(mediaType.Schema)
				if len(values) > 0 {
					tc.Body = values[0].Value
					tc.ContentType = ct
				}
			}
			break
		}
	}

	return tc
}

func (sf *StatefulFuzzer) ExtractResourceID(resourceType string, resp *core.HTTPResponse) string {
	var respData map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &respData); err != nil {
		return ""
	}

	idFields := []string{"id", "ID", "Id", "uuid", "UUID", "resource_id"}
	for _, field := range idFields {
		if val, ok := respData[field]; ok {
			return core.ToString(val)
		}
	}

	if data, ok := respData["data"].(map[string]interface{}); ok {
		for _, field := range idFields {
			if val, ok := data[field]; ok {
				return core.ToString(val)
			}
		}
	}

	return ""
}

func (sf *StatefulFuzzer) HandleTestResult(tc *core.TestCase, resp *core.HTTPResponse) {
	resourceType := getResourceType(tc.Operation.Path)
	if resourceType == "" {
		return
	}

	if tc.Operation.Method == "POST" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		resourceID := sf.ExtractResourceID(resourceType, resp)
		resource := core.Resource{
			ID:        resourceID,
			Type:      resourceType,
			Endpoint:  tc.Operation.Path,
			Method:    tc.Operation.Method,
			Response:  resp,
			CreatedAt: time.Now(),
		}
		sf.resourceContext.AddResource(resourceType, resource)
		sf.resourceContext.SetExtraction("resource_id:"+resourceType, resourceID)
	}
}

func (sf *StatefulFuzzer) CanRunTestCase(tc *core.TestCase) bool {
	if !tc.IsStateful {
		return true
	}

	for _, param := range tc.Operation.Parameters {
		if param.Location == core.ParamLocationPath {
			val, ok := tc.PathParams[param.Name]
			if !ok {
				continue
			}
			valStr := core.ToString(val)
			if strings.HasPrefix(valStr, "{{resource_id:") {
				resourceType := strings.TrimSuffix(strings.TrimPrefix(valStr, "{{resource_id:"), "}}")
				resource := sf.resourceContext.GetLatestResource(resourceType)
				if resource == nil || resource.Failed {
					return false
				}
			}
		}
	}

	return true
}

func (sf *StatefulFuzzer) ResolveTestCase(tc *core.TestCase) *core.TestCase {
	resolved := &core.TestCase{
		ID:           tc.ID,
		Seed:         tc.Seed,
		Operation:    tc.Operation,
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]interface{}),
		HeaderParams: make(map[string]interface{}),
		CookieParams: make(map[string]interface{}),
		Body:         tc.Body,
		ContentType:  tc.ContentType,
		Description:  tc.Description,
		IsStateful:   tc.IsStateful,
	}

	for k, v := range tc.QueryParams {
		resolved.QueryParams[k] = v
	}
	for k, v := range tc.HeaderParams {
		resolved.HeaderParams[k] = v
	}
	for k, v := range tc.CookieParams {
		resolved.CookieParams[k] = v
	}

	for k, v := range tc.PathParams {
		valStr := core.ToString(v)
		if strings.HasPrefix(valStr, "{{resource_id:") {
			resourceType := strings.TrimSuffix(strings.TrimPrefix(valStr, "{{resource_id:"), "}}")
			resource := sf.resourceContext.GetLatestResource(resourceType)
			if resource != nil && resource.ID != "" {
				resolved.PathParams[k] = resource.ID
			} else {
				resolved.PathParams[k] = v
			}
		} else {
			resolved.PathParams[k] = v
		}
	}

	return resolved
}

func (sf *StatefulFuzzer) GetResourceContext() *core.ResourceContext {
	return sf.resourceContext
}

func (sf *StatefulFuzzer) GetDependencyGraph() *core.DependencyGraph {
	return sf.dependencyGraph
}

func (sf *StatefulFuzzer) getResourceOperations() map[string][]*core.Operation {
	resourceOps := make(map[string][]*core.Operation)

	for path, methods := range sf.api.Paths {
		if core.ContainsString(sf.config.ExcludeEndpoints, path) {
			continue
		}
		resourceType := getResourceType(path)
		if resourceType == "" {
			continue
		}
		for _, op := range methods {
			resourceOps[resourceType] = append(resourceOps[resourceType], op)
		}
	}

	return resourceOps
}

func getResourceType(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if !strings.HasPrefix(part, "{") && !strings.HasSuffix(part, "}") {
			return part
		}
	}
	return ""
}

func hasPathParameters(path string) bool {
	return strings.Contains(path, "{") && strings.Contains(path, "}")
}

func GenerateIDORTargetUser(resourceType string, ownUserID string) string {
	return fmt.Sprintf("{{idor_target:%s}}", resourceType)
}

func (sf *StatefulFuzzer) GenerateIDORTestCases(otherUserToken string) []*core.TestCase {
	var testCases []*core.TestCase

	for resourceType, ops := range sf.getResourceOperations() {
		for _, op := range ops {
			if (op.Method == "GET" || op.Method == "PUT" || op.Method == "DELETE") && hasPathParameters(op.Path) {
				ownResource := sf.resourceContext.GetLatestResource(resourceType)
				if ownResource != nil && ownResource.ID != "" {
					tc := sf.createTestCase(op, resourceType)
					tc.IsStateful = true
					tc.Description = fmt.Sprintf("[IDOR Test] Access %s with different user token", resourceType)
					testCases = append(testCases, tc)
				}
			}
		}
	}

	return testCases
}
