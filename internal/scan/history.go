package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Manas-Sehgxl/inspect/internal/clocked"
)

// History remembers the last version of each script that was checked, so
// a scan can say what changed since then.
type History interface {
	Previous(source string) (*Snapshot, bool)
	Record(Snapshot)
}

type Snapshot struct {
	Source    string    `json:"source"`
	SHA256    string    `json:"sha256"`
	Body      string    `json:"body"`
	Decision  Decision  `json:"decision"`
	CheckedAt time.Time `json:"checked_at"`
}

// Change describes how a script differs from the last time it was checked.
type Change struct {
	Since        time.Time              `json:"since"`
	PrevSHA256   string                 `json:"prev_sha256"`
	PrevDecision Decision               `json:"prev_decision"`
	Added        int                    `json:"lines_added"`
	Removed      int                    `json:"lines_removed"`
	Compare      *clocked.CompareResult `json:"compare,omitempty"`
	Note         string                 `json:"note,omitempty"`
	PrevBody     string                 `json:"-"`
}

// ChangedLines returns the lines of passage whose text appears nowhere in
// other. Compare quotes whole blocks, sometimes starting or ending mid-line;
// this narrows a block to the lines that actually differ between versions.
func ChangedLines(passage, other string) []string {
	var out []string
	for _, l := range strings.Split(passage, "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.Contains(other, t) {
			out = append(out, l)
		}
	}
	return out
}

// Conflicts returns the passages Compare found to differ between the old
// and new versions.
func (c *Change) Conflicts() []clocked.CompareFinding {
	if c == nil || c.Compare == nil || len(c.Compare.Pairs) == 0 {
		return nil
	}
	return c.Compare.Pairs[0].Conflicts
}

// FileHistory stores one JSON file per source under Dir.
type FileHistory struct {
	Dir string
}

// DefaultHistory keeps history under the user cache directory.
func DefaultHistory() History {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil
	}
	return &FileHistory{Dir: filepath.Join(dir, "inspect", "history")}
}

func (h *FileHistory) path(source string) string {
	sum := sha256.Sum256([]byte(source))
	return filepath.Join(h.Dir, hex.EncodeToString(sum[:])+".json")
}

func (h *FileHistory) Previous(source string) (*Snapshot, bool) {
	data, err := os.ReadFile(h.path(source))
	if err != nil {
		return nil, false
	}
	var s Snapshot
	if json.Unmarshal(data, &s) != nil || s.Source != source {
		return nil, false
	}
	return &s, true
}

func (h *FileHistory) Record(s Snapshot) {
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	if os.MkdirAll(h.Dir, 0o700) == nil {
		os.WriteFile(h.path(s.Source), data, 0o600)
	}
}

// compareChars caps each version sent to Compare. Two versions must fit
// its 200,000-character, 58,000-token budget together.
const compareChars = 80_000

// diff fills sc.Changed when an earlier, different version of the script
// was checked before.
func (s *Scanner) diff(ctx context.Context, sc *Script, n int) {
	if s.History == nil || sc.Source == "stdin" {
		return
	}
	prev, ok := s.History.Previous(sc.Source)
	if !ok || prev.SHA256 == sc.SHA256 {
		return
	}
	ch := &Change{Since: prev.CheckedAt, PrevSHA256: prev.SHA256, PrevDecision: prev.Decision, PrevBody: prev.Body}
	ch.Added, ch.Removed = lineDelta(prev.Body, sc.Body)
	sc.Changed = ch

	if s.Opts.NoCompare {
		return
	}
	if utf8.RuneCountInString(prev.Body) > compareChars || utf8.RuneCountInString(sc.Body) > compareChars {
		ch.Note = "too large to compare"
		return
	}
	s.progress("[%d] Compare: diffing %s against the version checked %s", n, sc.Source, prev.CheckedAt.Format("Jan 2 15:04"))
	res, err := s.Client.Compare(ctx, clocked.CompareRequest{
		Documents: []clocked.Document{
			{ID: "before", Text: prev.Body},
			{ID: "after", Text: sc.Body},
		},
		// No custom instructions: with them Compare still rated the pair
		// conflicting but stopped returning the conflicting passages.
		Evidence: "all", // "flagged" also left the passages out
	})
	if err != nil {
		ch.Note = "compare failed: " + err.Error()
		return
	}
	ch.Compare = res
}

// lineDelta counts lines added and removed between two versions, ignoring
// order: a line that moved counts as neither.
func lineDelta(old, new string) (added, removed int) {
	counts := map[string]int{}
	for _, l := range strings.Split(old, "\n") {
		counts[l]++
	}
	for _, l := range strings.Split(new, "\n") {
		if counts[l] > 0 {
			counts[l]--
		} else {
			added++
		}
	}
	for _, n := range counts {
		removed += n
	}
	return added, removed
}
