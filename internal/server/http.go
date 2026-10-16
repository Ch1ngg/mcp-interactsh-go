package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ch1ngg/mcp-interactsh-go/internal/interactsh"
)

// HTTPOptions configures the network (HTTP + SSE) transports.
type HTTPOptions struct {
	Addr       string // listen address, e.g. ":8080" or "127.0.0.1:8080"
	Token      string // optional bearer token protecting every endpoint
	Streamable bool   // mount Streamable HTTP at /mcp
	SSE        bool   // mount legacy HTTP+SSE at /sse
}

// tokenMiddleware enforces the token on every request except /healthz.
// Accepted forms: "Authorization: Bearer <token>", "Authorization: <token>",
// or "X-Api-Key: <token>". Constant-time compared.
func tokenMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := ""
		if auth := r.Header.Get("Authorization"); auth != "" {
			got = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			got = strings.TrimSpace(strings.TrimPrefix(got, "bearer"))
		} else {
			got = r.Header.Get("X-Api-Key")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-interactsh-go"`)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"error":   map[string]any{"code": -32000, "message": "unauthorized: missing or invalid token"},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewHandler builds the HTTP mux with the selected transports.
func NewHandler(srv *mcp.Server, opts HTTPOptions) http.Handler {
	mux := http.NewServeMux()

	if opts.Streamable {
		mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	}
	if opts.SSE {
		mux.Handle("/sse", mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found; see /mcp (Streamable HTTP), /sse (HTTP+SSE), /healthz", http.StatusNotFound)
	})

	return tokenMiddleware(mux, opts.Token)
}

// RunHTTP serves the selected transports until ctx is cancelled.
func RunHTTP(ctx context.Context, srv *mcp.Server, opts HTTPOptions) error {
	handler := NewHandler(srv, opts)
	httpSrv := &http.Server{
		Addr:              opts.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", opts.Addr, err)
	}
	log.Printf("mcp-interactsh-go listening on %s (streamable=%v sse=%v auth=%v)",
		ln.Addr(), opts.Streamable, opts.SSE, opts.Token != "")

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// RunStdioAndForget exists for symmetry; stdio run is in server.go.
var _ = interactsh.SessionInfo{}
