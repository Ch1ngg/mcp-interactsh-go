// Package server wires the interactsh service into the Model Context Protocol:
// tool registration, stdio / streamable-HTTP / legacy-SSE transports, and
// bearer-token protection for the network transports.
package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ch1ngg/mcp-interactsh-go/internal/interactsh"
)

const probeInstructionsFmt = `Probing rules (very important):
- Build the host as: <correlation_id><nonce13>.<domain>
- correlation_id: exactly 20 lowercase hex characters (do not alter or truncate).
- nonce13: exactly 13 lowercase alphanumeric characters [a-z0-9] (no hyphens or uppercase).
- The label before the first dot must be length 33 (20 + 13).
- Requests to only <correlation_id>.<domain> (no nonce) will be ignored by interactsh.

Quick test (HTTP recommended): curl -I http://%s/
Then wait 2-3 seconds and call poll_interactsh_session with the same correlation_id to retrieve events.
If you still get zero events, send another probe or use filters (method, protocol, path_contains, text_contains) when polling.`

// ---- tool input/output types (JSON shapes match the Node bridge) ----

type createSessionInput struct {
	// Proxy is an optional HTTP/SOCKS5 URL used ONLY for this session's
	// outbound traffic to the interactsh server.
	Proxy string `json:"proxy,omitempty"`
}

type createSessionOutput struct {
	interactsh.SessionInfo
	Instructions    string `json:"instructions"`
	SampleProbeHost string `json:"sample_probe_host"`
}

type pollInput struct {
	CorrelationID string `json:"correlation_id"`
	Method        string `json:"method,omitempty"`
	PathContains  string `json:"path_contains,omitempty"`
	QueryContains string `json:"query_contains,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	TextContains  string `json:"text_contains,omitempty"`
}

type eventOut struct {
	Raw      string                  `json:"raw"`
	Protocol string                  `json:"protocol,omitempty"`
	HTTP     *interactsh.HTTPDetails `json:"http,omitempty"`
	Parsed   any                     `json:"parsed,omitempty"`
}

type pollOutput struct {
	AppliedFilters map[string]string `json:"applied_filters"`
	TotalEvents    int               `json:"total_events"`
	MatchedEvents  int               `json:"matched_events"`
	Events         []eventOut        `json:"events"`
	Extra          []string          `json:"extra"`
	TLDData        []string          `json:"tld_data"`
}

type correlationInput struct {
	CorrelationID string `json:"correlation_id"`
}

type deregisterOutput struct {
	Status        string `json:"status"`
	CorrelationID string `json:"correlation_id"`
}

// New builds an *mcp.Server with the four interactsh tools registered.
func New(service *interactsh.Service, version string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "interactsh-bridge", Version: version}, nil)

	mcp.AddTool(srv,
		&mcp.Tool{
			Name:        "create_interactsh_session",
			Description: "Generates credentials, registers with interactsh, and returns the connection details.",
		},
		func(ctx context.Context, req *mcp.CallToolRequest, in createSessionInput) (*mcp.CallToolResult, createSessionOutput, error) {
			info, err := service.CreateSession(ctx, in.Proxy)
			if err != nil {
				return nil, createSessionOutput{}, err
			}
			domain := service.DomainSuffix()
			probeHost := info.CorrelationID + interactsh.RandomNonce13()
			if domain != "" {
				probeHost += "." + domain
			}
			return nil, createSessionOutput{
				SessionInfo:     info,
				Instructions:    fmt.Sprintf(probeInstructionsFmt, probeHost),
				SampleProbeHost: probeHost,
			}, nil
		},
	)

	mcp.AddTool(srv,
		&mcp.Tool{
			Name:        "list_interactsh_sessions",
			Description: "Lists interactsh sessions cached in memory.",
		},
		func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, map[string]interactsh.SessionInfo, error) {
			return nil, service.List(), nil
		},
	)

	mcp.AddTool(srv,
		&mcp.Tool{
			Name:        "poll_interactsh_session",
			Description: "Retrieves and decrypts interactions for a session. Optional filters let you match HTTP method, path, query, protocol, or free text.",
		},
		func(ctx context.Context, req *mcp.CallToolRequest, in pollInput) (*mcp.CallToolResult, pollOutput, error) {
			res, err := service.Poll(ctx, in.CorrelationID)
			if err != nil {
				return nil, pollOutput{}, err
			}
			filters := interactsh.Filters{
				Method:        in.Method,
				PathContains:  in.PathContains,
				QueryContains: in.QueryContains,
				Protocol:      in.Protocol,
				TextContains:  in.TextContains,
			}
			matched := interactsh.ApplyFilters(res.Events, filters)
			events := make([]eventOut, 0, len(matched))
			for _, ev := range matched {
				events = append(events, eventOut{Raw: ev.Raw, Protocol: ev.Protocol, HTTP: ev.HTTP, Parsed: ev.Parsed})
			}
			return nil, pollOutput{
				AppliedFilters: filters.NonEmpty(),
				TotalEvents:    len(res.Events),
				MatchedEvents:  len(events),
				Events:         events,
				Extra:          res.Extra,
				TLDData:        res.TLDData,
			}, nil
		},
	)

	mcp.AddTool(srv,
		&mcp.Tool{
			Name:        "deregister_interactsh_session",
			Description: "Removes a session from interactsh and local cache.",
		},
		func(ctx context.Context, req *mcp.CallToolRequest, in correlationInput) (*mcp.CallToolResult, deregisterOutput, error) {
			if err := service.Deregister(ctx, in.CorrelationID); err != nil {
				return nil, deregisterOutput{}, err
			}
			return nil, deregisterOutput{Status: "deregistered", CorrelationID: in.CorrelationID}, nil
		},
	)

	return srv
}

// RunStdio serves the MCP server over stdin/stdout.
func RunStdio(ctx context.Context, srv *mcp.Server) error {
	return srv.Run(ctx, &mcp.StdioTransport{})
}
