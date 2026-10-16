package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ch1ngg/mcp-interactsh-go/internal/interactsh"
)

const testToken = "top-secret-token"

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	svc, err := interactsh.NewService(interactsh.Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(svc, "test")
	return NewHandler(srv, HTTPOptions{Addr: ":0", Token: testToken, Streamable: true, SSE: true})
}

func TestTokenAuth(t *testing.T) {
	h := newTestHandler(t)

	// healthz is exempt.
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("healthz = %d", w.Code)
	}

	// Missing token.
	r = httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("no-token = %d, want 401", w.Code)
	}

	// Wrong token.
	r = httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer wrong")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("wrong token = %d, want 401", w.Code)
	}

	// Right token (raw, no Bearer) passes the gate and reaches the SDK.
	r = httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 401 {
		t.Fatal("valid raw token rejected")
	}
}

// initialize over Streamable HTTP with the Bearer token.
func TestStreamableHTTPInitialize(t *testing.T) {
	h := newTestHandler(t)

	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "0"},
		},
	}
	raw, _ := json.Marshal(body)

	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("initialize = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Mcp-Session-Id") == "" {
		t.Fatal("no session id header")
	}
	if !strings.Contains(w.Body.String(), "interactsh-bridge") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

// tools/list over legacy SSE: open stream, read endpoint event, POST initialize.
func TestLegacySSEEndpointEvent(t *testing.T) {
	h := newTestHandler(t)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("sse = %d", resp.StatusCode)
	}

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	first := string(buf[:n])
	if !strings.Contains(first, "event: endpoint") {
		t.Fatalf("no endpoint event: %q", first)
	}
	if !strings.Contains(first, "sessionid=") {
		t.Fatalf("endpoint event without session id: %q", first)
	}
}
