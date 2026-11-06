package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// cacheTTL is how long a verdict is reused for identical script contents.
const cacheTTL = 24 * time.Hour

// Cache remembers verdicts by script hash so an agent re-running the same
// script doesn't pay for another check. A nil *Cache caches nothing.
type Cache struct {
	Dir string
}

type cacheEntry struct {
	Decision  scan.Decision `json:"decision"`
	Summary   string        `json:"summary"`
	CheckedAt time.Time     `json:"checked_at"`
}

// DefaultCache stores verdicts under the user cache directory.
func DefaultCache() *Cache {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil
	}
	return &Cache{Dir: filepath.Join(dir, "inspect", "verdicts")}
}

func (c *Cache) path(body string) string {
	sum := sha256.Sum256([]byte(body))
	return filepath.Join(c.Dir, hex.EncodeToString(sum[:])+".json")
}

func (c *Cache) Get(body string) (scan.Decision, string, bool) {
	if c == nil {
		return 0, "", false
	}
	data, err := os.ReadFile(c.path(body))
	if err != nil {
		return 0, "", false
	}
	var e cacheEntry
	if json.Unmarshal(data, &e) != nil || time.Since(e.CheckedAt) > cacheTTL {
		return 0, "", false
	}
	return e.Decision, e.Summary, true
}

// Put stores a verdict. Scans that followed nested downloads aren't cached:
// the root script can stay the same while what it downloads changes.
func (c *Cache) Put(body string, rep *scan.Report, summary string) {
	if c == nil || len(rep.Scripts) != 1 {
		return
	}
	for _, d := range rep.Scripts[0].Downloads {
		if d.Executed {
			return
		}
	}
	data, err := json.Marshal(cacheEntry{Decision: rep.Decision, Summary: summary, CheckedAt: time.Now()})
	if err != nil {
		return
	}
	if os.MkdirAll(c.Dir, 0o700) == nil {
		os.WriteFile(c.path(body), data, 0o600)
	}
}
