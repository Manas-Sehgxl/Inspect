// Package serve is the local HTTP server the browser extension talks to.
// It keeps the Clocked key out of the browser and reuses the same checks as
// the CLI.
//
// Any web page can try to call a server on localhost, so every request must
// pass three checks: the Host header names this server (against DNS
// rebinding), the Origin, if any, is a browser extension, and the request
// carries the pairing token. The server also only ever checks remote
// scripts; a web page can't make it read local files.
package serve

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Manas-Sehgxl/inspect/internal/hook"
	"github.com/Manas-Sehgxl/inspect/internal/report"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

const DefaultPort = 7878

// maxPageChars caps the page text an extension may send.
const maxPageChars = 100_000

type Server struct {
	Port       int
	Token      string
	NewScanner func() (*scan.Scanner, error)

	// Trial accounts allow one Clocked request at a time, so checks from
	// several tabs run one after another.
	mu sync.Mutex
}

// CheckRequest is what the extension sends for a command it found on a page.
type CheckRequest struct {
	Command  string `json:"command"`
	PageURL  string `json:"page_url"`
	PageText string `json:"page_text"`
}

type CheckResponse struct {
	Ran      bool          `json:"ran"` // false: the command runs no remote script
	Decision scan.Decision `json:"decision"`
	Results  []Result      `json:"results,omitempty"`
	Problems []string      `json:"problems,omitempty"` // scripts that couldn't be checked
}

type Result struct {
	Script string      `json:"script"`
	View   report.View `json:"view"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/check", s.check)
	return s.guard(mux)
}

// ListenAndServe serves on 127.0.0.1 only.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", s.Port),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// guard applies the Host, Origin and token checks to every request.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil || (host != "127.0.0.1" && host != "localhost") || port != fmt.Sprint(s.Port) {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !extensionOrigin(o) {
			http.Error(w, "web pages can't use this server", http.StatusForbidden)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extensionOrigin(o string) bool {
	for _, p := range []string{"chrome-extension://", "moz-extension://", "safari-web-extension://"} {
		if strings.HasPrefix(o, p) {
			return true
		}
	}
	return false
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if r := []rune(req.PageText); len(r) > maxPageChars {
		req.PageText = string(r[:maxPageChars])
	}

	var resp CheckResponse
	for _, f := range hook.Find(req.Command, "") {
		if !f.Remote {
			continue // never read local files for a web page
		}
		resp.Ran = true
		if f.Dynamic {
			resp.Decision = max(resp.Decision, scan.Warn)
			resp.Problems = append(resp.Problems, fmt.Sprintf("%s is built at run time, so it can't be checked ahead of time", f.Source))
			continue
		}
		rep, err := s.run(r.Context(), scan.Target{Source: f.Source, Remote: true, Page: req.PageURL, PageText: req.PageText})
		if err != nil {
			resp.Decision = max(resp.Decision, scan.Warn)
			resp.Problems = append(resp.Problems, fmt.Sprintf("couldn't check %s: %v", f.Source, err))
			continue
		}
		resp.Decision = max(resp.Decision, rep.Decision)
		resp.Results = append(resp.Results, Result{Script: f.Source, View: report.NewView(rep)})
	}
	writeJSON(w, resp)
}

func (s *Server) run(ctx context.Context, t scan.Target) (*scan.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, err := s.NewScanner()
	if err != nil {
		return nil, err
	}
	return sc.Run(ctx, t)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// LoadToken reads the pairing token from the user config directory,
// creating one the first time.
func LoadToken() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "inspect", "serve-token")
	if data, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(data)); t != "" {
			return t, nil
		}
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return t, os.WriteFile(path, []byte(t+"\n"), 0o600)
}
