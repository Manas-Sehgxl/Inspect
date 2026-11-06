package serve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

func TestGuard(t *testing.T) {
	s := &Server{Port: 7878, Token: "secret", NewScanner: func() (*scan.Scanner, error) {
		panic("scanner used")
	}}
	h := s.Handler()

	tests := []struct {
		name   string
		host   string
		origin string
		token  string
		want   int
	}{
		{"extension", "127.0.0.1:7878", "chrome-extension://abc", "secret", 200},
		{"firefox extension", "localhost:7878", "moz-extension://abc", "secret", 200},
		{"no origin (curl)", "127.0.0.1:7878", "", "secret", 200},
		{"web page", "127.0.0.1:7878", "https://evil.example", "secret", 403},
		{"dns rebinding", "evil.example:7878", "", "secret", 403},
		{"wrong port in host", "127.0.0.1:9999", "", "secret", 403},
		{"no token", "127.0.0.1:7878", "chrome-extension://abc", "", 401},
		{"wrong token", "127.0.0.1:7878", "chrome-extension://abc", "nope", 401},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/v1/status", nil)
		req.Host = tt.host
		if tt.origin != "" {
			req.Header.Set("Origin", tt.origin)
		}
		if tt.token != "" {
			req.Header.Set("Authorization", "Bearer "+tt.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s: status %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
}

// A page asking about a local script gets nothing back: the server only
// checks remote scripts.
func TestCheckIgnoresLocalScripts(t *testing.T) {
	s := &Server{Port: 7878, Token: "secret", NewScanner: func() (*scan.Scanner, error) {
		panic("scanner used")
	}}
	body := `{"command":"bash /etc/passwd; bash ~/.ssh/id_ed25519","page_url":"https://x"}`
	req := httptest.NewRequest("POST", "/v1/check", strings.NewReader(body))
	req.Host = "127.0.0.1:7878"
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ran":false`) {
		t.Errorf("status %d, body %s", rec.Code, rec.Body.String())
	}
}
