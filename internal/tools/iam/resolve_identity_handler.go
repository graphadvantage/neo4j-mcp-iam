// Copyright (c) "Neo4j"
// Neo4j Sweden AB [http://neo4j.com]

package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/neo4j/mcp/internal/auth"
	"github.com/neo4j/mcp/internal/tools"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
)

const resolveIdentityQuery = `
MATCH (u)
WHERE u.schemaId IS NULL
  AND any(label IN labels(u) WHERE label IN ['User', 'Principal'])
  AND any(key IN ['username', 'email', 'mail', 'userPrincipalName', 'upn', 'name', 'id']
          WHERE u[key] IS NOT NULL AND toLower(toString(u[key])) = toLower($principal))
OPTIONAL MATCH (u)-[:MEMBER_OF|MEMBER_OF_GROUP|IN_GROUP|HAS_GROUP*1..]->(g)
WHERE g.schemaId IS NULL
WITH u, collect(DISTINCT g) AS groups
RETURN
  labels(u) AS principalLabels,
  properties(u) AS principalProperties,
  coalesce(u.AdGroupList, []) AS adGroupList,
  [g IN groups WHERE g IS NOT NULL | {
    labels: labels(g),
    properties: properties(g),
    name: coalesce(g.name, g.group, g.displayName, g.email, g.mail, g.id)
  }] AS groups
LIMIT 1
`

type IdentityResolution struct {
	Principal           string             `json:"principal"`
	Source              string             `json:"source"`
	IAMNodeFound        bool               `json:"iamNodeFound"`
	PrincipalLabels     []string           `json:"principalLabels,omitempty"`
	PrincipalProperties map[string]any     `json:"principalProperties,omitempty"`
	Groups              []ResolvedIAMGroup `json:"groups"`
	AuthzPrincipals     []string           `json:"authzPrincipals"`
	Notes               []string           `json:"notes,omitempty"`
}

type ResolvedIAMGroup struct {
	Labels     []string       `json:"labels"`
	Properties map[string]any `json:"properties"`
	Name       string         `json:"name,omitempty"`
}

// ResolveIdentityHandler returns a handler function for the resolve-identity tool.
func ResolveIdentityHandler(deps *tools.ToolDependencies) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleResolveIdentity(ctx, request, deps)
	}
}

func handleResolveIdentity(ctx context.Context, request mcp.CallToolRequest, deps *tools.ToolDependencies) (*mcp.CallToolResult, error) {
	if deps.DBService == nil {
		errMessage := "database service is not initialized"
		slog.Error(errMessage)
		return mcp.NewToolResultError(errMessage), nil
	}

	var args ResolveIdentityInput
	if err := request.BindArguments(&args); err != nil {
		slog.Error("error binding arguments", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	principal, source, notes := resolvePrincipal(ctx)
	if principal == "" {
		return mcp.NewToolResultError("Unable to resolve principal. In STDIO clients such as Claude Desktop, set NEO4J_MCP_PRINCIPAL to the user's stable identity, for example michael.moore@neo4j.com."), nil
	}
	if strings.TrimSpace(args.Principal) != "" {
		if !impersonationAllowed() {
			return mcp.NewToolResultError("principal override requires NEO4J_MCP_ALLOW_IMPERSONATION=true"), nil
		}
		principal = strings.TrimSpace(args.Principal)
		source = "impersonation-request"
		notes = append(notes, "Principal was supplied by the tool caller for test impersonation.")
	}

	records, err := deps.DBService.ExecuteReadQuery(ctx, resolveIdentityQuery, map[string]any{
		"principal": principal,
	})
	if err != nil {
		slog.Error("failed to resolve identity from IAM graph", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	resolution := IdentityResolution{
		Principal:       principal,
		Source:          source,
		Groups:          []ResolvedIAMGroup{},
		AuthzPrincipals: uniqueStrings([]string{principal, "everyone"}),
		Notes:           notes,
	}

	if len(records) > 0 {
		if err := applyIdentityRecord(&resolution, records[0]); err != nil {
			slog.Error("failed to process IAM identity record", "error", err)
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	if !resolution.IAMNodeFound {
		resolution.Notes = append(resolution.Notes, "No matching :User or :Principal node was found in the IAM graph.")
	}

	out, err := json.MarshalIndent(resolution, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func impersonationAllowed() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("NEO4J_MCP_ALLOW_IMPERSONATION")))
	return value == "true" || value == "1" || value == "yes"
}

func resolvePrincipal(ctx context.Context) (string, string, []string) {
	if username, _, ok := auth.GetBasicAuthCredentials(ctx); ok && strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username), "basic-auth-username", nil
	}

	if token, ok := auth.GetBearerToken(ctx); ok {
		if principal := principalFromJWT(token); principal != "" {
			return principal, "bearer-jwt-claim", []string{"Bearer JWT claims are decoded locally for identity discovery; production deployments should validate issuer, audience, and signature before trusting claims for authorization."}
		}
	}

	for _, key := range []string{"NEO4J_MCP_PRINCIPAL", "NEO4J_MCP_AUTH_SUBJECT", "USER_EMAIL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value, "env:" + key, nil
		}
	}

	return "", "", nil
}

func principalFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	for _, key := range []string{"preferred_username", "upn", "email", "unique_name", "sub"} {
		if value, ok := claims[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func applyIdentityRecord(resolution *IdentityResolution, record *neo4j.Record) error {
	resolution.IAMNodeFound = true

	if labelsRaw, ok := record.Get("principalLabels"); ok {
		labels, err := stringSlice(labelsRaw)
		if err != nil {
			return fmt.Errorf("invalid principalLabels: %w", err)
		}
		resolution.PrincipalLabels = labels
	}

	if propsRaw, ok := record.Get("principalProperties"); ok {
		props, ok := propsRaw.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid principalProperties")
		}
		resolution.PrincipalProperties = props
	}

	if groupsRaw, ok := record.Get("groups"); ok {
		groupMaps, ok := groupsRaw.([]any)
		if !ok {
			return fmt.Errorf("invalid groups")
		}
		authzPrincipals := append([]string{}, resolution.AuthzPrincipals...)
		for _, groupRaw := range groupMaps {
			groupMap, ok := groupRaw.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid group entry")
			}
			group := ResolvedIAMGroup{}
			if labelsRaw, ok := groupMap["labels"]; ok {
				labels, err := stringSlice(labelsRaw)
				if err != nil {
					return fmt.Errorf("invalid group labels: %w", err)
				}
				group.Labels = labels
			}
			if propsRaw, ok := groupMap["properties"]; ok {
				props, ok := propsRaw.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid group properties")
				}
				group.Properties = props
			}
			if name, ok := groupMap["name"].(string); ok {
				group.Name = name
				authzPrincipals = append(authzPrincipals, name)
			}
			resolution.Groups = append(resolution.Groups, group)
		}
		resolution.AuthzPrincipals = uniqueStrings(authzPrincipals)
	}

	if adGroupsRaw, ok := record.Get("adGroupList"); ok {
		adGroups, err := stringSlice(adGroupsRaw)
		if err != nil {
			return fmt.Errorf("invalid adGroupList: %w", err)
		}
		resolution.AuthzPrincipals = uniqueStrings(append(resolution.AuthzPrincipals, adGroups...))
	}

	return nil
}

func stringSlice(value any) ([]string, error) {
	rawValues, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list")
	}
	values := make([]string, 0, len(rawValues))
	for _, raw := range rawValues {
		value, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected string")
		}
		values = append(values, value)
	}
	return values, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
