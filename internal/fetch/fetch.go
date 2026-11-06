// Package fetch downloads scripts the way a shell one-liner would and finds
// the further downloads a script makes.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	// A character is at most 4 bytes, so this is enough to fill MaxChars.
	data, err := get(ctx, url, UserAgent, 4*MaxChars+1)
	if err != nil {
		return "", false, err
	}
	body, truncated = Limit(data)
	return body, truncated, nil
}

// Page downloads a web page, such as the install instructions a script
// came from, the way a browser would ask for it.
func Page(ctx context.Context, url string) (string, error) {
	return get(ctx, url, "Mozilla/5.0 (X11; Linux x86_64) inspect", 5<<20)
}

func get(ctx context.Context, url, agent string, limit int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", brief(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return string(data), err
}

// brief drops the "Get <url>:" wrapper and dial details from a request
// error; callers already say which URL failed.
func brief(err error) error {
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound {
		return errors.New("host not found")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Limit cuts s to MaxChars characters.
func Limit(s string) (string, bool) {
	if utf8.RuneCountInString(s) <= MaxChars {
		return s, false
	}
	return string([]rune(s)[:MaxChars]), true
}
