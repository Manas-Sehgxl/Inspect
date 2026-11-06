// Package clocked is a small client for the Clocked API
// (https://clocked.rezolve.ai/docs). It covers the endpoints Inspect uses:
// /script (Inspect), /injection (Guard), /pii (Protect), /compare (Compare)
// and /grounding (Verify).
package clocked

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const DefaultBaseURL = "https://clocked.rezolve.ai/clocked"

const maxRetries = 4

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	mu      sync.Mutex
	credits float64
}

func New(apiKey string) *Client {
	return &Client{
		BaseURL: DefaultBaseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 2 * time.Minute},
	}
}

// Credits returns the total credits debited so far, as reported by the
// X-Clocked-Credits response header.
func (c *Client) Credits() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.credits
}

// APIError is a non-2xx response from Clocked.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("clocked: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) Script(ctx context.Context, req ScriptRequest) (*ScriptResult, error) {
	var out ScriptResult
	return &out, c.post(ctx, "/script", req, &out)
}

func (c *Client) Injection(ctx context.Context, req InjectionRequest) (*InjectionResult, error) {
	var out InjectionResult
	return &out, c.post(ctx, "/injection", req, &out)
}

func (c *Client) PII(ctx context.Context, req PIIRequest) (*PIIResult, error) {
	var out PIIResult
	return &out, c.post(ctx, "/pii", req, &out)
}

func (c *Client) Compare(ctx context.Context, req CompareRequest) (*CompareResult, error) {
	var out CompareResult
	return &out, c.post(ctx, "/compare", req, &out)
}

func (c *Client) Grounding(ctx context.Context, req GroundingRequest) (*GroundingResult, error) {
	var out GroundingResult
	return &out, c.post(ctx, "/grounding", req, &out)
}

// post sends one logical request. Retries reuse the same Idempotency-Key so
// Clocked can tell a retry from a new request and won't bill it twice.
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	key := newIdempotencyKey()

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)

		resp, err := c.HTTP.Do(req)
		if err != nil {
			if attempt < maxRetries && ctx.Err() == nil {
				if err := sleep(ctx, backoff(attempt)); err != nil {
					return err
				}
				continue
			}
			return err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		c.addCredits(resp.Header.Get("X-Clocked-Credits"))

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			if attempt < maxRetries {
				if err := sleep(ctx, retryAfter(resp, attempt)); err != nil {
					return err
				}
				continue
			}
		}
		if resp.StatusCode >= 300 {
			return &APIError{Status: resp.StatusCode, Body: string(data)}
		}
		return json.Unmarshal(data, out)
	}
}

func (c *Client) addCredits(h string) {
	if h == "" {
		return
	}
	n, err := strconv.ParseFloat(h, 64)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.credits += n
	c.mu.Unlock()
}

func backoff(attempt int) time.Duration {
	return time.Second << attempt // 1s, 2s, 4s, 8s
}

func retryAfter(resp *http.Response, attempt int) time.Duration {
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return backoff(attempt)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// newIdempotencyKey returns a random UUID (version 4).
func newIdempotencyKey() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
