// Package fetch downloads scripts the way a shell one-liner would and finds
// the further downloads a script makes.
package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"
)

// MaxChars is Inspect's admission limit for one script.
const MaxChars = 200_000

// UserAgent mimics curl. Some servers send different content to browsers and
// to curl, and we want to see what `curl ... | bash` would actually get.
const UserAgent = "curl/8.11.1"

var client = &http.Client{Timeout: 30 * time.Second}

// Get downloads url and returns its body. Bodies over MaxChars are cut short
// and truncated is set.
func Get(ctx context.Context, url string) (body string, truncated bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	// A character is at most 4 bytes, so this is enough to fill MaxChars.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4*MaxChars+1))
	if err != nil {
		return "", false, err
	}
	body, truncated = Limit(string(data))
	return body, truncated, nil
}

// Limit cuts s to MaxChars characters.
func Limit(s string) (string, bool) {
	if utf8.RuneCountInString(s) <= MaxChars {
		return s, false
	}
	return string([]rune(s)[:MaxChars]), true
}
