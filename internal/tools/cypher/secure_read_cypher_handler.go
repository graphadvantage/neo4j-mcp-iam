// Copyright (c) "Neo4j"
// Neo4j Sweden AB [http://neo4j.com]

package cypher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/neo4j/mcp/internal/auth"
	"github.com/neo4j/mcp/internal/tools"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
)

const secureAuthPrincipalParam = "__secure_auth_principal"

var cypherIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func SecureReadCypherHandler(deps *tools.ToolDependencies) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleSecureReadCypher(ctx, request, deps)
	}
}

func handleSecureReadCypher(ctx context.Context, request mcp.CallToolRequest, deps *tools.ToolDependencies) (*mcp.CallToolResult, error) {
	if deps.DBService == nil {
		errMessage := "Database service is not initialized"
		slog.Error(errMessage)
		return mcp.NewToolResultError(errMessage), nil
	}

	var args SecureReadCypherInput
	if err := request.BindArguments(&args); err != nil {
		slog.Error("error binding arguments", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	query := strings.TrimSpace(args.Query)
	if query == "" {
		errMessage := "Query parameter is required and cannot be empty"
		slog.Error(errMessage)
		return mcp.NewToolResultError(errMessage), nil
	}

	if err := validateSecureGeneratedFragment(query); err != nil {
		slog.Error("rejected insecure generated cypher", "error", err, "query", query)
		return mcp.NewToolResultError(err.Error()), nil
	}

	protectedVariables, err := normalizeCypherIdentifiers(args.ProtectedVariables, "protectedVariables")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if len(protectedVariables) == 0 {
		return mcp.NewToolResultError("protectedVariables must list at least one returned node variable to authorize"), nil
	}

	returnVariables := args.ReturnVariables
	if len(returnVariables) == 0 {
		returnVariables = protectedVariables
	}
	returnVariables, err = normalizeCypherIdentifiers(returnVariables, "returnVariables")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	scopeVariables := mergeCypherIdentifiers(protectedVariables, returnVariables)

	finalReturn, err := secureFinalReturn(args.FinalReturn, returnVariables)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	principal := resolveSecurePrincipal(ctx)
	if principal == "" {
		return mcp.NewToolResultError("Unable to resolve principal. In STDIO clients such as Claude Desktop, set NEO4J_MCP_PRINCIPAL to the user's stable identity."), nil
	}
	if strings.TrimSpace(args.Principal) != "" {
		if !secureImpersonationAllowed() {
			return mcp.NewToolResultError("principal override requires NEO4J_MCP_ALLOW_IMPERSONATION=true"), nil
		}
		principal = strings.TrimSpace(args.Principal)
	}

	params, err := secureReadParams(args.Params, principal)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	wrappedQuery := buildSecureReadQuery(query, protectedVariables, scopeVariables, finalReturn)

	slog.Info("executing secure read cypher query", "query", wrappedQuery)

	queryType, err := deps.DBService.GetQueryType(ctx, wrappedQuery, params)
	if err != nil {
		slog.Error("error classifying secure cypher query", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}
	if queryType != neo4j.QueryTypeReadOnly {
		errMessage := "secure-read-cypher can only run read-only Cypher statements"
		slog.Error("rejected non-read secure query", "type", queryType, "query", wrappedQuery)
		return mcp.NewToolResultError(errMessage), nil
	}

	records, err := deps.DBService.ExecuteReadQuery(ctx, wrappedQuery, params)
	if err != nil {
		slog.Error("error executing secure cypher query", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	response, err := deps.DBService.Neo4jRecordsToJSON(records)
	if err != nil {
		slog.Error("error formatting secure query results", "error", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(response), nil
}

func validateSecureGeneratedFragment(query string) error {
	normalized := strings.ToLower(stripCypherLineComments(query))
	if strings.Contains(normalized, ";") {
		return fmt.Errorf("secure-read-cypher accepts exactly one Cypher fragment; semicolons are not allowed")
	}

	blockedPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b(return|create|merge|delete|detach\s+delete|set|remove|drop|alter|grant|deny|revoke|load\s+csv|periodic\s+commit|use|profile)\b`),
		regexp.MustCompile(`\bcall\s+(dbms|db\.|apoc|gds)\.`),
	}
	for _, pattern := range blockedPatterns {
		if pattern.MatchString(normalized) {
			return fmt.Errorf("generated query fragment contains a clause or procedure that is not allowed by secure-read-cypher")
		}
	}
	return nil
}

func buildSecureReadQuery(generatedQuery string, protectedVariables []string, scopeVariables []string, finalReturn string) string {
	protectedList := strings.Join(protectedVariables, ", ")
	scopeList := strings.Join(append([]string{"authz"}, scopeVariables...), ", ")

	return fmt.Sprintf(`
CALL {
  MATCH (u)
  WHERE u.schemaId IS NULL
    AND any(label IN labels(u) WHERE label IN ['User', 'Principal'])
    AND any(key IN ['username', 'email', 'mail', 'userPrincipalName', 'upn', 'name', 'id']
            WHERE u[key] IS NOT NULL AND toLower(toString(u[key])) = toLower($%s))
  OPTIONAL MATCH (u)-[:MEMBER_OF|MEMBER_OF_GROUP|IN_GROUP|HAS_GROUP*1..]->(g)
  WHERE g.schemaId IS NULL
  WITH u,
       collect(DISTINCT coalesce(g.name, g.group, g.displayName, g.email, g.mail, g.id)) AS groupPrincipals
  RETURN {
    principalId: coalesce(u.id, u.email, u.userPrincipalName, u.upn, u.name),
    tenantId: u.tenantId,
    authzPrincipals: [p IN groupPrincipals + coalesce(u.AdGroupList, []) + [
      coalesce(u.username, u.email, u.userPrincipalName, u.upn, u.name, u.id),
      'everyone'
    ] WHERE p IS NOT NULL]
  } AS authz
}
CALL {
  WITH authz
  %s
  RETURN %s
}
WITH %s
WHERE all(resource IN [%s] WHERE resource IS NULL OR (
  (authz.tenantId IS NULL OR resource.tenantId IS NULL OR resource.tenantId = authz.tenantId)
  AND any(principal IN coalesce(resource['Permissions.Read'], [])
          WHERE principal IN authz.authzPrincipals)
))
%s`, secureAuthPrincipalParam, generatedQuery, strings.Join(scopeVariables, ", "), scopeList, protectedList, finalReturn)
}

func normalizeCypherIdentifiers(values []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !cypherIdentifierPattern.MatchString(value) {
			return nil, fmt.Errorf("%s contains invalid Cypher identifier %q", field, value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func mergeCypherIdentifiers(first []string, second []string) []string {
	seen := make(map[string]struct{}, len(first)+len(second))
	merged := make([]string, 0, len(first)+len(second))
	for _, values := range [][]string{first, second} {
		for _, value := range values {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			merged = append(merged, value)
		}
	}
	return merged
}

func secureFinalReturn(finalReturn string, returnVariables []string) (string, error) {
	finalReturn = strings.TrimSpace(finalReturn)
	if finalReturn == "" {
		return "RETURN " + strings.Join(returnVariables, ", "), nil
	}

	normalized := strings.ToLower(stripCypherLineComments(finalReturn))
	if strings.Contains(normalized, ";") {
		return "", fmt.Errorf("finalReturn must not contain semicolons")
	}
	if !strings.HasPrefix(normalized, "return ") && normalized != "return" {
		return "", fmt.Errorf("finalReturn must be a RETURN clause")
	}

	blockedPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b(match|with|call|create|merge|delete|detach\s+delete|set|remove|drop|alter|grant|deny|revoke|load\s+csv|periodic\s+commit|use|profile|unwind)\b`),
	}
	for _, pattern := range blockedPatterns {
		if pattern.MatchString(normalized) {
			return "", fmt.Errorf("finalReturn contains a clause that is not allowed")
		}
	}
	return finalReturn, nil
}

func secureReadParams(params Params, principal string) (map[string]any, error) {
	secureParams := make(map[string]any, len(params)+1)
	for key, value := range params {
		if key == secureAuthPrincipalParam {
			return nil, fmt.Errorf("params cannot include reserved key %q", secureAuthPrincipalParam)
		}
		secureParams[key] = value
	}
	secureParams[secureAuthPrincipalParam] = principal
	return secureParams, nil
}

func resolveSecurePrincipal(ctx context.Context) string {
	if username, _, ok := auth.GetBasicAuthCredentials(ctx); ok && strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username)
	}
	if token, ok := auth.GetBearerToken(ctx); ok {
		if principal := principalFromSecureJWT(token); principal != "" {
			return principal
		}
	}
	for _, key := range []string{"NEO4J_MCP_PRINCIPAL", "NEO4J_MCP_AUTH_SUBJECT", "USER_EMAIL"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func secureImpersonationAllowed() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("NEO4J_MCP_ALLOW_IMPERSONATION")))
	return value == "true" || value == "1" || value == "yes"
}

func principalFromSecureJWT(token string) string {
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

func stripCypherLineComments(query string) string {
	lines := strings.Split(query, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "//"); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}
