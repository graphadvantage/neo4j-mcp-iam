// Copyright (c) "Neo4j"
// Neo4j Sweden AB [http://neo4j.com]

package iam

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	db "github.com/neo4j/mcp/internal/database/mocks"
	"github.com/neo4j/mcp/internal/tools"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"go.uber.org/mock/gomock"
)

func TestResolveIdentityHandler(t *testing.T) {
	t.Run("resolves principal from Claude Desktop env fallback", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "michael.moore@neo4j.com")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDB := db.NewMockService(ctrl)
		mockDB.EXPECT().
			ExecuteReadQuery(gomock.Any(), resolveIdentityQuery, map[string]any{"principal": "michael.moore@neo4j.com"}).
			Return([]*neo4j.Record{}, nil)

		result, err := ResolveIdentityHandler(&tools.ToolDependencies{DBService: mockDB})(context.Background(), mcp.CallToolRequest{})
		if err != nil {
			t.Fatalf("expected no handler error, got %v", err)
		}
		if result == nil || result.IsError {
			t.Fatalf("expected successful tool result, got %#v", result)
		}

		var resolution IdentityResolution
		if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &resolution); err != nil {
			t.Fatalf("failed to parse identity result: %v", err)
		}
		if resolution.Principal != "michael.moore@neo4j.com" {
			t.Fatalf("principal = %q, want michael.moore@neo4j.com", resolution.Principal)
		}
		if resolution.Source != "env:NEO4J_MCP_PRINCIPAL" {
			t.Fatalf("source = %q, want env:NEO4J_MCP_PRINCIPAL", resolution.Source)
		}
		if resolution.IAMNodeFound {
			t.Fatal("expected no IAM node to be found")
		}
	})

	t.Run("adds resolved group names to authz principals", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "michael.moore@neo4j.com")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDB := db.NewMockService(ctrl)
		mockDB.EXPECT().
			ExecuteReadQuery(gomock.Any(), resolveIdentityQuery, map[string]any{"principal": "michael.moore@neo4j.com"}).
			Return([]*neo4j.Record{
				{
					Keys: []string{"principalLabels", "principalProperties", "groups"},
					Values: []any{
						[]any{"User"},
						map[string]any{"email": "michael.moore@neo4j.com"},
						[]any{
							map[string]any{
								"labels":     []any{"Group"},
								"properties": map[string]any{"name": "group2"},
								"name":       "group2",
							},
						},
					},
				},
			}, nil)

		result, err := ResolveIdentityHandler(&tools.ToolDependencies{DBService: mockDB})(context.Background(), mcp.CallToolRequest{})
		if err != nil {
			t.Fatalf("expected no handler error, got %v", err)
		}
		if result == nil || result.IsError {
			t.Fatalf("expected successful tool result, got %#v", result)
		}

		var resolution IdentityResolution
		if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &resolution); err != nil {
			t.Fatalf("failed to parse identity result: %v", err)
		}
		if !resolution.IAMNodeFound {
			t.Fatal("expected IAM node to be found")
		}
		if !containsString(resolution.AuthzPrincipals, "group2") {
			t.Fatalf("authzPrincipals = %#v, want group2", resolution.AuthzPrincipals)
		}
		if !containsString(resolution.AuthzPrincipals, "everyone") {
			t.Fatalf("authzPrincipals = %#v, want everyone", resolution.AuthzPrincipals)
		}
	})

	t.Run("resolves requested principal when impersonation is enabled", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "michael.moore@neo4j.com")
		t.Setenv("NEO4J_MCP_ALLOW_IMPERSONATION", "true")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDB := db.NewMockService(ctrl)
		mockDB.EXPECT().
			ExecuteReadQuery(gomock.Any(), resolveIdentityQuery, map[string]any{"principal": "johnny.kinnaird@neo4j.com"}).
			Return([]*neo4j.Record{}, nil)

		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"principal": "johnny.kinnaird@neo4j.com",
				},
			},
		}

		result, err := ResolveIdentityHandler(&tools.ToolDependencies{DBService: mockDB})(context.Background(), request)
		if err != nil {
			t.Fatalf("expected no handler error, got %v", err)
		}
		if result == nil || result.IsError {
			t.Fatalf("expected successful tool result, got %#v", result)
		}

		var resolution IdentityResolution
		if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &resolution); err != nil {
			t.Fatalf("failed to parse identity result: %v", err)
		}
		if resolution.Principal != "johnny.kinnaird@neo4j.com" {
			t.Fatalf("principal = %q, want johnny.kinnaird@neo4j.com", resolution.Principal)
		}
		if resolution.Source != "impersonation-request" {
			t.Fatalf("source = %q, want impersonation-request", resolution.Source)
		}
	})

	t.Run("rejects requested principal when impersonation is disabled", func(t *testing.T) {
		t.Setenv("NEO4J_MCP_PRINCIPAL", "michael.moore@neo4j.com")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDB := db.NewMockService(ctrl)
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]any{
					"principal": "johnny.kinnaird@neo4j.com",
				},
			},
		}

		result, err := ResolveIdentityHandler(&tools.ToolDependencies{DBService: mockDB})(context.Background(), request)
		if err != nil {
			t.Fatalf("expected no handler error, got %v", err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("expected error result, got %#v", result)
		}
	})
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
