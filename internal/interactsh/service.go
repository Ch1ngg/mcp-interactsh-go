// Package interactsh implements a minimal client for the public interactsh
// protocol: register / poll / deregister, with RSA-OAEP + AES-256-CFB event
// decryption, mirroring the semantics of the reference Node bridge
// (github.com/tachote/mcp-interactsh).
package interactsh

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options configures a Service.
type Options struct {
	// BaseURL of the interactsh server, e.g. https://oast.pro
	BaseURL string
	// DomainSuffix used for callback hosts; defaults to the host of BaseURL.
	DomainSuffix string
	// Token is sent verbatim in the Authorization header when the interactsh
	// server enforces auth.
	Token string
	// Proxy is an optional HTTP/SOCKS5 proxy URL for all outbound traffic.
	// When empty, HTTP_PROXY / HTTPS_PROXY / NO_PROXY env vars apply.
	Proxy string
}

// SessionInfo is the JSON shape returned to MCP clients.
type SessionInfo struct {
	CorrelationID  string `json:"correlation_id"`
	SecretKey      string `json:"secret_key"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	CallbackDomain string `json:"callback_domain"`
	ServerURL      string `json:"server_url"`
}

type session struct {
	info   SessionInfo
	priv   *rsa.PrivateKey // session private key for event decryption
	client *http.Client    // per-session client (honors per-session proxy)
}

// PollResult is the decrypted server response of GET /poll.
type PollResult struct {
	Events  []string
	Extra   []string
	TLDData []string
}

// Service manages interactsh sessions.
type Service struct {
	baseURL      string
	domainSuffix string
	token        string
	client       *http.Client

	mu       sync.RWMutex
	sessions map[string]*session
}

// NewService validates options and builds the proxy-aware HTTP client.
func NewService(opts Options) (*Service, error) {
	baseURL := strings.TrimRight(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://oast.pro"
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	domain := opts.DomainSuffix
	if domain == "" {
		domain = u.Hostname()
	}

	client, err := newHTTPClient(opts.Proxy)
	if err != nil {
		return nil, err
	}

	return &Service{
		baseURL:      baseURL,
		domainSuffix: domain,
		token:        opts.Token,
		client:       client,
		sessions:     map[string]*session{},
	}, nil
}

// BaseURL returns the configured interactsh server URL.
func (s *Service) BaseURL() string { return s.baseURL }

// DomainSuffix returns the callback domain suffix.
func (s *Service) DomainSuffix() string { return s.domainSuffix }

// newHTTPClient builds a client honoring: explicit proxy URL > proxy env vars.
func newHTTPClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse proxy url: %w", err)
		}
		transport.Proxy = http.ProxyURL(pu)
	} else {
		// Standard env chain: HTTPS_PROXY / HTTP_PROXY / ALL_PROXY / NO_PROXY.
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second}, nil
}

// CreateSession generates keys, registers with interactsh and caches the session.
// A non-empty proxyOverride gives this single session its own outbound proxy,
// leaving other sessions (and other MCP tools) untouched.
func (s *Service) CreateSession(ctx context.Context, proxyOverride string) (SessionInfo, error) {
	keys, err := GenerateKeys()
	if err != nil {
		return SessionInfo{}, err
	}
	correlationID, err := RandomCorrelationID()
	if err != nil {
		return SessionInfo{}, err
	}
	secretKey, err := RandomSecretKey()
	if err != nil {
		return SessionInfo{}, err
	}

	callbackDomain := correlationID
	if s.domainSuffix != "" {
		callbackDomain = correlationID + "." + s.domainSuffix
	}

	info := SessionInfo{
		CorrelationID:  correlationID,
		SecretKey:      secretKey,
		PrivateKeyPEM:  keys.PrivateKeyPEM,
		CallbackDomain: callbackDomain,
		ServerURL:      s.baseURL,
	}

	client := s.client
	if proxyOverride != "" {
		client, err = newHTTPClient(proxyOverride)
		if err != nil {
			return SessionInfo{}, err
		}
	}

	sess := &session{info: info, priv: keys.PrivateKey, client: client}

	payload := map[string]string{
		"public-key":     keys.PublicKeyB64,
		"secret-key":     secretKey,
		"correlation-id": correlationID,
	}
	if err := s.doRequest(ctx, client, http.MethodPost, "/register", payload, nil); err != nil {
		return SessionInfo{}, fmt.Errorf("register: %w", err)
	}

	s.mu.Lock()
	s.sessions[correlationID] = sess
	s.mu.Unlock()
	return info, nil
}

// List returns a snapshot of all cached sessions.
func (s *Service) List() map[string]SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]SessionInfo, len(s.sessions))
	for id, sess := range s.sessions {
		out[id] = sess.info
	}
	return out
}

func (s *Service) requireSession(correlationID string) (*session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[correlationID]
	if !ok {
		return nil, fmt.Errorf("unknown correlation_id: %s", correlationID)
	}
	return sess, nil
}

type pollResponse struct {
	Data    json.RawMessage `json:"data"`
	AESKey  string          `json:"aes_key"`
	Extra   json.RawMessage `json:"extra"`
	TLDData json.RawMessage `json:"tlddata"`
}

// Poll fetches and decrypts new interactions for a session.
func (s *Service) Poll(ctx context.Context, correlationID string) (*PollResult, error) {
	sess, err := s.requireSession(correlationID)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("id", correlationID)
	q.Set("secret", sess.info.SecretKey)

	var payload pollResponse
	if err := s.doRequest(ctx, sess.client, http.MethodGet, "/poll?"+q.Encode(), nil, &payload); err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}

	result := &PollResult{
		Events:  normaliseArray(payload.Data),
		Extra:   normaliseArray(payload.Extra),
		TLDData: normaliseArray(payload.TLDData),
	}
	if len(result.Events) == 0 || payload.AESKey == "" {
		return result, nil
	}

	aesKey, err := DecryptAESKey(sess.priv, payload.AESKey)
	if err != nil {
		return nil, err
	}
	decrypted := make([]string, 0, len(result.Events))
	for _, enc := range result.Events {
		plain, err := DecryptPayload(aesKey, enc)
		if err != nil {
			return nil, fmt.Errorf("decrypt event: %w", err)
		}
		decrypted = append(decrypted, plain)
	}
	result.Events = decrypted
	return result, nil
}

// Deregister removes the session server-side and locally.
func (s *Service) Deregister(ctx context.Context, correlationID string) error {
	sess, err := s.requireSession(correlationID)
	if err != nil {
		return err
	}
	payload := map[string]string{
		"correlation-id": correlationID,
		"secret-key":     sess.info.SecretKey,
	}
	if err := s.doRequest(ctx, sess.client, http.MethodPost, "/deregister", payload, nil); err != nil {
		return fmt.Errorf("deregister: %w", err)
	}
	s.mu.Lock()
	delete(s.sessions, correlationID)
	s.mu.Unlock()
	return nil
}

func (s *Service) doRequest(ctx context.Context, client *http.Client, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.token != "" {
		// interactsh expects the raw token (no Bearer prefix), like the Node bridge.
		req.Header.Set("Authorization", s.token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &e) == nil {
			if e.Error != "" {
				msg = e.Error
			} else if e.Message != "" {
				msg = e.Message
			}
		}
		return fmt.Errorf("interactsh responded %d: %s", resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// normaliseArray turns null / single string / array into []string.
func normaliseArray(raw json.RawMessage) []string {
	out := []string{}
	if len(raw) == 0 || string(raw) == "null" {
		return out
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, item := range arr {
			out = append(out, strings.Trim(string(item), `"`))
		}
		return out
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		out = append(out, single)
	}
	return out
}
