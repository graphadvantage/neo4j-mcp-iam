// Copyright (c) "Neo4j"
// Neo4j Sweden AB [http://neo4j.com]

package iam

import "github.com/mark3labs/mcp-go/mcp"

type ResolveIdentityInput struct {
	Principal string `json:"principal,omitempty" jsonschema:"Optional principal to resolve for test impersonation. Requires NEO4J_MCP_ALLOW_IMPERSONATION=true."`
}

func ResolveIdentitySpec() mcp.Tool {
	return mcp.NewTool("resolve-identity",
		mcp.WithDescription("Resolve the current authenticated principal and look up matching IAM graph group memberships. A principal override may be supplied only when test impersonation is explicitly enabled."),
		mcp.WithInputSchema[ResolveIdentityInput](),
		mcp.WithTitleAnnotation("Resolve Identity"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}
