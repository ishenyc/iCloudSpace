package httpapi

import (
	"strconv"
	"strings"
)

// The template is static and discloses no installation-specific configuration.
const managementOpenAPIDefault = "/admin/api/control/v1"

type managementOperation struct {
	Method, Path, ID, Summary, Request, Response string
	Status                                       int
	Query                                        []any
	Description, Stream                          string
	RequestRequired, Sensitive                   bool
	Responses                                    openObject
}

func managementServer() []any {
	return []any{openObject{"url": "{management_base}", "variables": openObject{"management_base": openObject{"default": managementOpenAPIDefault, "description": "Fixed same-origin /admin/api/control/v1. Static protocol description; no installation discovery or authentication bypass."}}}}
}

// mergeManagementOpenAPI only merges authored protocol descriptions. It cannot
// access an installation, discover its entry, or execute a management request.
func mergeManagementOpenAPI(spec openObject) {
	components := spec["components"].(openObject)
	schemas := components["schemas"].(openObject)
	for _, group := range []openObject{managementCommonSchemas(), managementAccountSchemas(), managementWorkflowSchemas()} {
		for name, value := range group {
			if _, exists := schemas[name]; exists {
				panic("httpapi: duplicate management schema " + name)
			}
			schemas[name] = value
		}
	}
	security := components["securitySchemes"].(openObject)
	security["ManagementSession"] = openObject{"type": "apiKey", "in": "cookie", "name": "space_session", "description": "Same-origin operator session; HttpOnly, SameSite=Strict, Path=M. Mailbox/deployment Bearer does not confer this authority."}
	security["ManagementCSRF"] = openObject{"type": "apiKey", "in": "header", "name": "X-CSRF-Token", "description": "Existing CSRF returned by GET M/session, bound to the session and checked with the exact same Origin. Never silently minted by safe reads."}
	paths := spec["paths"].(openObject)
	operations := append(managementAccountRoutes(), managementWorkflowRoutes()...)
	operations = append(operations, managementMailRoutes()...)
	for _, descriptor := range operations {
		item, exists := paths[descriptor.Path].(openObject)
		if !exists {
			item = openObject{}
			paths[descriptor.Path] = item
		}
		method := strings.ToLower(descriptor.Method)
		if _, exists := item[method]; exists {
			panic("httpapi: duplicate management operation " + descriptor.ID)
		}
		item[method] = managementOpenOperation(descriptor)
	}
	info := spec["info"].(openObject)
	info["title"] = "iCloudSpace canonical API"
	info["description"] = "Public mailbox and management APIs. Management operations use /admin/api/control/v1. Authentication, request formats, response schemas and side effects are documented for each operation. Installation-specific values and secrets are not included."
}

func managementOpenOperation(d managementOperation) openObject {
	if d.Response == "" && d.Stream == "" && len(d.Responses) == 0 {
		panic("httpapi: management response schema omitted " + d.ID)
	}
	status := d.Status
	if status == 0 {
		status = 200
	}
	responses := openObject{}
	if d.Response != "" {
		responses[strconv.Itoa(status)] = openResponse("Typed result; preserve original receipt/key on uncertainty.", openEnvelope(openRef(d.Response)))
	}
	for _, code := range []string{"400", "401", "403", "404", "409", "410", "413", "422", "429", "500", "502", "503"} {
		responses[code] = openResponse("Controlled failure. An unknown outcome permits original-resource query only, never automatic replay.", openRef("Failure"))
	}
	for code, response := range d.Responses {
		responses[code] = response
	}
	security := []any{openObject{"ManagementSession": []string{}}}
	parameters := append([]any{}, d.Query...)
	unsafe := d.Method != "GET" && d.Method != "HEAD"
	if unsafe {
		security = []any{openObject{"ManagementSession": []string{}, "ManagementCSRF": []string{}}}
		parameters = append(parameters, openParameter("Origin", "header", openString(), true))
	}
	if d.ID == "m.auth.createSession" || d.ID == "m.auth.readSession" {
		security = []any{}
	}
	for _, name := range []string{"source_id", "address_id", "group_id", "attempt_id", "operation_key", "delivery_key", "uid", "part"} {
		if !strings.Contains(d.Path, "{"+name+"}") {
			continue
		}
		schema := any(openRef("Identifier"))
		if name == "uid" {
			schema = openRef("UID")
		} else if name == "part" {
			schema = openObject{"type": "string", "pattern": "^(root|[1-9][0-9]*(\\.[1-9][0-9]*)*)$"}
		} else if strings.HasSuffix(name, "_key") {
			maximum := 128
			if strings.Contains(d.Path, "credential-rotation") || strings.Contains(d.Path, "credential-deliveries") {
				maximum = 256
			}
			schema = openObject{"type": "string", "minLength": 1, "maxLength": maximum, "description": "Original opaque imported/issued key, preserved exactly. Query does not allocate a replacement."}
		}
		parameters = append(parameters, openParameter(name, "path", schema, true))
	}
	op := openObject{"operationId": d.ID, "summary": d.Summary, "description": d.Description, "servers": managementServer(), "security": security, "responses": responses, "x-management-template": true, "x-sensitive-read": d.Sensitive}
	if len(parameters) != 0 {
		op["parameters"] = parameters
	}
	if d.Request != "" {
		op["requestBody"] = openObject{"required": d.RequestRequired, "content": openJSON(openRef(d.Request)), "description": "One application/json object; unknown fields/multiple documents rejected. Endpoint byte budget and exact CAS/key rules apply; duplicate-member rejection is not universal."}
	}
	if d.Response == "MProviderAuth" || d.Response == "MHMEOperation" || d.Response == "MMailSubmission" || d.Response == "MComposeContext" {
		responses["202"] = openResponse("Recorded pending/unknown/partial durability; query original key. Not retry permission or delivery proof.", openEnvelope(openRef(d.Response)))
	}
	return op
}
