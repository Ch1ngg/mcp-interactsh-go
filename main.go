// Command mcp-interactsh-go exposes ProjectDiscovery's interactsh as a Model
// Context Protocol server (Go port of tachote/mcp-interactsh) with stdio,
// Streamable HTTP and legacy HTTP+SSE transports, bearer-token protection and
// proxy support.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Ch1ngg/mcp-interactsh-go/internal/interactsh"
	"github.com/Ch1ngg/mcp-interactsh-go/internal/server"
)

var version = "dev"

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func usage() {
	fmt.Fprintf(os.Stderr, `mcp-interactsh-go %s — interactsh as an MCP server (stdio / HTTP / SSE)

Usage:
  mcp-interactsh-go [flags]

Transports:
  --transport stdio      MCP over stdin/stdout (default; for Claude Code, Cursor, Codex, ...)
  --transport http       Streamable HTTP at http://<addr>/mcp      (MCP 2025-03-26+)
  --transport sse        Legacy HTTP+SSE at http://<addr>/sse      (MCP 2024-11-05)
  --transport http+sse   Both of the above on one listener

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, `
Environment:
  INTERACTSH_BASE_URL        default interactsh server (flag: --base-url)
  INTERACTSH_DOMAIN_SUFFIX   callback domain suffix    (flag: --domain-suffix)
  INTERACTSH_TOKEN           interactsh server auth    (flag: --interactsh-token)
  INTERACTSH_PROXY           outbound proxy for interactsh traffic (flag: --proxy)
                             falls back to HTTPS_PROXY / HTTP_PROXY / NO_PROXY
  MCP_TRANSPORT              stdio | http | sse | http+sse (flag: --transport)
  MCP_ADDR                   listen address for http/sse  (flag: --addr)
  MCP_TOKEN / MCP_AUTH_TOKEN bearer token protecting the HTTP/SSE endpoints (flag: --token)`)
}

func main() {
	flag.Usage = usage
	var (
		baseURL   = flag.String("base-url", envOr("INTERACTSH_BASE_URL", "https://oast.pro"), "interactsh server base URL")
		domain    = flag.String("domain-suffix", os.Getenv("INTERACTSH_DOMAIN_SUFFIX"), "callback domain suffix (default: host of --base-url)")
		isToken   = flag.String("interactsh-token", os.Getenv("INTERACTSH_TOKEN"), "Authorization token if the interactsh server enforces auth")
		proxy     = flag.String("proxy", os.Getenv("INTERACTSH_PROXY"), "HTTP/SOCKS5 proxy URL for outbound interactsh traffic (default: env HTTPS_PROXY/HTTP_PROXY)")
		transport = flag.String("transport", envOr("MCP_TRANSPORT", "stdio"), "stdio | http | sse | http+sse")
		addr      = flag.String("addr", envOr("MCP_ADDR", ":8080"), "listen address for http/sse transports")
		token     = flag.String("token", envOr("MCP_TOKEN", os.Getenv("MCP_AUTH_TOKEN")), "bearer token required by the HTTP/SSE endpoints (empty = no auth)")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("mcp-interactsh-go " + version)
		return
	}

	if *domain == "" {
		if u, err := url.Parse(*baseURL); err == nil {
			*domain = u.Hostname()
		}
	}

	service, err := interactsh.NewService(interactsh.Options{
		BaseURL:      strings.TrimRight(*baseURL, "/"),
		DomainSuffix: *domain,
		Token:        *isToken,
		Proxy:        *proxy,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	srv := server.New(service, version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch strings.ToLower(*transport) {
	case "stdio", "":
		if err := server.RunStdio(ctx, srv); err != nil {
			fmt.Fprintln(os.Stderr, "fatal:", err)
			os.Exit(1)
		}
	case "http", "sse", "http+sse", "sse+http":
		opts := server.HTTPOptions{
			Addr:       *addr,
			Token:      *token,
			SSE:        strings.Contains(*transport, "sse"),
			Streamable: strings.Contains(*transport, "http"),
		}
		if *transport == "sse" {
			opts.Streamable = false
		}
		if err := server.RunHTTP(ctx, srv, opts); err != nil {
			fmt.Fprintln(os.Stderr, "fatal:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "fatal: unknown transport:", *transport)
		os.Exit(1)
	}
}
