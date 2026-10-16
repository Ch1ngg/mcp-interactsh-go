package interactsh

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// fakeInteractsh simulates the three endpoints of an interactsh server,
// encrypting poll data exactly like the real one (OAEP-SHA256 wrapped AES-256
// key, AES-256-CFB payloads).
type fakeInteractsh struct {
	ts *httptest.Server

	mu      sync.Mutex
	secrets map[string]string // correlation-id -> secret-key
	pubKeys map[string]*rsa.PublicKey
	dropped map[string]bool // deregistered
	events  []string
	sawAuth string
}

func newFakeInteractsh(t *testing.T) *fakeInteractsh {
	t.Helper()
	f := &fakeInteractsh{
		secrets: map[string]string{},
		pubKeys: map[string]*rsa.PublicKey{},
		dropped: map[string]bool{},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.sawAuth = r.Header.Get("Authorization")
		f.mu.Unlock()

		var body struct {
			PublicKeyB64  string `json:"public-key"`
			SecretKey     string `json:"secret-key"`
			CorrelationID string `json:"correlation-id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", 400)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(body.PublicKeyB64)
		if err != nil {
			http.Error(w, "bad pubkey", 400)
			return
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			http.Error(w, "pubkey not PEM", 400)
			return
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			http.Error(w, "bad spki", 400)
			return
		}
		f.mu.Lock()
		f.pubKeys[body.CorrelationID] = pub.(*rsa.PublicKey)
		f.secrets[body.CorrelationID] = body.SecretKey
		f.mu.Unlock()
		w.WriteHeader(200)
	})

	mux.HandleFunc("GET /poll", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		secret := r.URL.Query().Get("secret")
		f.mu.Lock()
		wantSecret, ok := f.secrets[id]
		pub := f.pubKeys[id]
		events := append([]string{}, f.events...)
		f.mu.Unlock()
		if !ok || wantSecret != secret {
			http.Error(w, `{"error":"invalid session"}`, 401)
			return
		}

		aesKey := make([]byte, 32)
		rand.Read(aesKey)
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
		if err != nil {
			http.Error(w, "encrypt fail", 500)
			return
		}
		block, _ := aes.NewCipher(aesKey)
		encrypted := make([]string, 0, len(events))
		for _, ev := range events {
			iv := make([]byte, aes.BlockSize)
			rand.Read(iv)
			ct := make([]byte, len(ev))
			cipher.NewCTR(block, iv).XORKeyStream(ct, []byte(ev)) // current fleet: AES-CTR
			encrypted = append(encrypted, base64.StdEncoding.EncodeToString(append(iv, ct...)))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"aes_key": base64.StdEncoding.EncodeToString(wrapped),
			"data":    encrypted,
			"extra":   []string{"extra-item"},
			"tlddata": "single-tld",
		})
	})

	mux.HandleFunc("POST /deregister", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CorrelationID string `json:"correlation-id"`
			SecretKey     string `json:"secret-key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.dropped[body.CorrelationID] = true
		f.mu.Unlock()
		w.WriteHeader(200)
	})

	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeInteractsh) setEvents(events ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = events
}

func TestServiceLifecycle(t *testing.T) {
	fake := newFakeInteractsh(t)
	svc, err := NewService(Options{BaseURL: fake.ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	if svc.DomainSuffix() == "" {
		t.Fatal("domain suffix should default to base URL host")
	}

	ctx := context.Background()
	info, err := svc.CreateSession(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if info.CallbackDomain != info.CorrelationID+"."+svc.DomainSuffix() {
		t.Fatalf("callback domain: %q", info.CallbackDomain)
	}
	if len(svc.List()) != 1 {
		t.Fatal("session not cached")
	}

	fake.setEvents(
		`{"protocol":"http","raw-request":"GET /probe?x=1 HTTP/1.1\r\nHost: h\r\n"}`,
		`{"protocol":"dns","raw":"lookup"}`,
	)
	res, err := svc.Poll(ctx, info.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 || res.Events[0] == "" {
		t.Fatalf("decrypted events wrong: %+v", res.Events)
	}
	matched := ApplyFilters(res.Events, Filters{Method: "GET"})
	if len(matched) != 1 || matched[0].HTTP.Path != "/probe" {
		t.Fatalf("filter over decrypted events failed: %+v", matched)
	}
	if len(res.Extra) != 1 || res.Extra[0] != "extra-item" {
		t.Fatalf("extra: %+v", res.Extra)
	}
	if len(res.TLDData) != 1 || res.TLDData[0] != "single-tld" {
		t.Fatalf("tlddata: %+v", res.TLDData)
	}

	if err := svc.Deregister(ctx, info.CorrelationID); err != nil {
		t.Fatal(err)
	}
	if len(svc.List()) != 0 {
		t.Fatal("session not removed locally")
	}
	fake.mu.Lock()
	dropped := fake.dropped[info.CorrelationID]
	fake.mu.Unlock()
	if !dropped {
		t.Fatal("deregister not forwarded to server")
	}
}

func TestServiceUnknownSession(t *testing.T) {
	svc, _ := NewService(Options{BaseURL: "http://127.0.0.1:1"})
	if _, err := svc.Poll(context.Background(), "deadbeef"); err == nil {
		t.Fatal("expected error for unknown session")
	}
}

func TestInteractshTokenForwarded(t *testing.T) {
	fake := newFakeInteractsh(t)
	svc, _ := NewService(Options{BaseURL: fake.ts.URL, Token: "server-token-123"})
	if _, err := svc.CreateSession(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	auth := fake.sawAuth
	fake.mu.Unlock()
	if auth != "server-token-123" {
		t.Fatalf("Authorization header = %q", auth)
	}
}

// TestPerSessionProxyOverride: global traffic stays direct, the session created
// with a proxy override is routed through the proxy.
func TestPerSessionProxyOverride(t *testing.T) {
	fake := newFakeInteractsh(t)

	var proxied atomicBool
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.set(true)
		// Classic HTTP forward proxy: absolute-URI request; re-issue against target.
		outReq, _ := http.NewRequestWithContext(r.Context(), r.Method, r.RequestURI, r.Body)
		outReq.Header = r.Header.Clone()
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxySrv.Close()

	svc, _ := NewService(Options{BaseURL: fake.ts.URL})

	// Direct session: must not touch the proxy.
	if _, err := svc.CreateSession(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if proxied.get() {
		t.Fatal("direct session went through proxy")
	}

	// Proxied session: must be routed via proxySrv.
	info, err := svc.CreateSession(context.Background(), proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !proxied.get() {
		t.Fatal("proxy override session did not use the proxy")
	}
	if _, err := svc.Poll(context.Background(), info.CorrelationID); err != nil {
		t.Fatal(err)
	}
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set(v bool) { b.mu.Lock(); b.v = v; b.mu.Unlock() }
func (b *atomicBool) get() bool  { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

func TestInvalidProxyURL(t *testing.T) {
	if _, err := NewService(Options{BaseURL: "http://x", Proxy: "://bad"}); err == nil {
		t.Fatal("expected proxy parse error")
	}
	if _, err := NewService(Options{BaseURL: "://bad"}); err == nil {
		t.Fatal("expected base url parse error")
	}
}
