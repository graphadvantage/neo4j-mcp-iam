// Copyright (c) "Neo4j"
// Neo4j Sweden AB [http://neo4j.com]

package cypher

import "github.com/mark3labs/mcp-go/mcp"

type SecureReadCypherInput struct {
	Query              string   `json:"query" jsonschema:"The generated read-only Cypher match fragment to execute after the IAM auth prelude. The fragment must not include RETURN."`
	Params             Params   `json:"params,omitempty" jsonschema:"Parameters to pass to the generated Cypher fragment"`
	ProtectedVariables []string `json:"protectedVariables" jsonschema:"Node variables that must pass IAM authorization checks before rows or aggregates are returned"`
	ReturnVariables    []string `json:"returnVariables,omitempty" jsonschema:"Variables that must remain in scope for the final return clause. Defaults to protectedVariables."`
	FinalReturn        string   `json:"finalReturn,omitempty" jsonschema:"Final RETURN clause to apply after IAM filtering, for example RETURN count(DISTINCT j) AS readableExecutedJobCount. Defaults to returning returnVariables."`
	Principal          string   `json:"principal,omitempty" jsonschema:"Optional principal to use for test impersonation. Requires NEO4J_MCP_ALLOW_IMPERSONATION=true."`
}

func SecureReadCypherSpec() mcp.Tool {
	return mcp.NewTool("secure-read-cypher",
		mcp.WithDescription("secure-read-cypher composes an IAM authorization prelude, a generated read-only Cypher match fragment, an IAM permissions filter, and a final RETURN clause. Aggregations belong in finalReturn so they run after authorization filtering."),
		mcp.WithInputSchema[SecureReadCypherInput](),
		mcp.WithTitleAnnotation("Secure Read Cypher"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}
