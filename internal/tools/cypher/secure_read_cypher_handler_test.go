// Copyright (c) "Neo4j"
// Neo4j Sweden AB [http://neo4j.com]

package cypher_test

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	analytics "github.com/neo4j/mcp/internal/analytics/mocks"
	db "github.com/neo4j/mcp/internal/database/mocks"
	"github.com/neo4j/mcp/internal/tools"
	"github.com/neo4j/mcp/internal/tools/cypher"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"go.uber.org/mock/gomock"
)

func TestSecureReadCypherHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	analyticsService := analytics.NewMockService(ctrl)
	defer ctrl.Finish()

	t.Run("wraps generated read query with IAM authorization", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "alice@example.com")

		mockDB := db.NewMockService(ctrl)
		mockDB.EXPECT().
			GetQueryType(gomock.Any(), gomock.Cond(func(query string) bool {
				return strings.Contains(query, "MATCH (d:Document)-[:ABOUT]->(p:Project)") &&
					strings.Contains(query, "$__secure_auth_principal") &&
					strings.Contains(query, "authzPrincipals") &&
					strings.Contains(query, "resource['Permissions.Read']") &&
					strings.Contains(query, "RETURN d, p\n}") &&
					strings.Contains(query, "WITH authz, d, p") &&
					strings.Contains(query, "RETURN d, p")
			}), map[string]any{
				"project":                 "Apollo",
				"__secure_auth_principal": "alice@example.com",
			}).
			Return(neo4j.QueryTypeReadOnly, nil)
		mockDB.EXPECT().
			ExecuteReadQuery(gomock.Any(), gomock.Any(), map[string]any{
				"project":                 "Apollo",
				"__secure_auth_principal": "alice@example.com",
			}).
			Return([]*neo4j.Record{}, nil)
		mockDB.EXPECT().
			Neo4jRecordsToJSON(gomock.Any()).
			Return(`[{"d": {"title": "Plan"}}]`, nil)

		deps := &tools.ToolDependencies{
			DBService:        mockDB,
			AnalyticsService: analyticsService,
		}
		handler := cypher.SecureReadCypherHandler(deps)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"query":              "MATCH (d:Document)-[:ABOUT]->(p:Project) WHERE p.name = $project",
					"params":             map[string]any{"project": "Apollo"},
					"protectedVariables": []any{"d"},
					"returnVariables":    []any{"d", "p"},
				},
			},
		}

		result, err := handler(context.Background(), request)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil || result.IsError {
			t.Error("Expected success result")
		}
	})

	t.Run("supports filtered aggregation in final return", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "alice@example.com")
		t.Setenv("NEO4J_MCP_ALLOW_IMPERSONATION", "true")

		mockDB := db.NewMockService(ctrl)
		mockDB.EXPECT().
			GetQueryType(gomock.Any(), gomock.Cond(func(query string) bool {
				return strings.Contains(query, "MATCH (a)-[:EXECUTES]->(j:Job)") &&
					strings.Contains(query, "RETURN j\n}") &&
					strings.Contains(query, "WITH authz, j") &&
					strings.Contains(query, "WHERE all(resource IN [j]") &&
					strings.Contains(query, "RETURN count(DISTINCT j) AS readableExecutedJobCount")
			}), map[string]any{
				"__secure_auth_principal": "johnny.kinnaird@neo4j.com",
			}).
			Return(neo4j.QueryTypeReadOnly, nil)
		mockDB.EXPECT().
			ExecuteReadQuery(gomock.Any(), gomock.Any(), map[string]any{
				"__secure_auth_principal": "johnny.kinnaird@neo4j.com",
			}).
			Return([]*neo4j.Record{}, nil)
		mockDB.EXPECT().
			Neo4jRecordsToJSON(gomock.Any()).
			Return(`[{"readableExecutedJobCount": 3}]`, nil)

		deps := &tools.ToolDependencies{
			DBService:        mockDB,
			AnalyticsService: analyticsService,
		}
		handler := cypher.SecureReadCypherHandler(deps)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"query":              "MATCH (a)-[:EXECUTES]->(j:Job)",
					"protectedVariables": []any{"j"},
					"finalReturn":        "RETURN count(DISTINCT j) AS readableExecutedJobCount",
					"principal":          "johnny.kinnaird@neo4j.com",
				},
			},
		}

		result, err := handler(context.Background(), request)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil || result.IsError {
			t.Error("Expected success result for filtered aggregation")
		}
	})

	t.Run("rejects principal override unless impersonation is enabled", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "alice@example.com")

		mockDB := db.NewMockService(ctrl)
		deps := &tools.ToolDependencies{
			DBService:        mockDB,
			AnalyticsService: analyticsService,
		}
		handler := cypher.SecureReadCypherHandler(deps)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"query":              "MATCH (a)-[:EXECUTES]->(j:Job)",
					"protectedVariables": []any{"j"},
					"principal":          "johnny.kinnaird@neo4j.com",
				},
			},
		}

		result, err := handler(context.Background(), request)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil || !result.IsError {
			t.Error("Expected error result for disabled impersonation")
		}
	})

	t.Run("rejects return in generated fragment", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "alice@example.com")

		mockDB := db.NewMockService(ctrl)
		deps := &tools.ToolDependencies{
			DBService:        mockDB,
			AnalyticsService: analyticsService,
		}
		handler := cypher.SecureReadCypherHandler(deps)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"query":              "MATCH (d:Document) RETURN d",
					"protectedVariables": []any{"d"},
				},
			},
		}

		result, err := handler(context.Background(), request)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil || !result.IsError {
			t.Error("Expected error result for RETURN in generated fragment")
		}
	})

	t.Run("requires protected variables", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "alice@example.com")

		mockDB := db.NewMockService(ctrl)
		deps := &tools.ToolDependencies{
			DBService:        mockDB,
			AnalyticsService: analyticsService,
		}
		handler := cypher.SecureReadCypherHandler(deps)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"query": "MATCH (d:Document)",
				},
			},
		}

		result, err := handler(context.Background(), request)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil || !result.IsError {
			t.Error("Expected error result for missing protected variables")
		}
	})

	t.Run("rejects reserved secure parameter", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "alice@example.com")

		mockDB := db.NewMockService(ctrl)
		deps := &tools.ToolDependencies{
			DBService:        mockDB,
			AnalyticsService: analyticsService,
		}
		handler := cypher.SecureReadCypherHandler(deps)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"query":              "MATCH (d:Document)",
					"params":             map[string]any{"__secure_auth_principal": "mallory@example.com"},
					"protectedVariables": []any{"d"},
				},
			},
		}

		result, err := handler(context.Background(), request)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil || !result.IsError {
			t.Error("Expected error result for reserved parameter")
		}
	})
}
