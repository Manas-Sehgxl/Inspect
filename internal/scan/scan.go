// Package scan inspects a script and every script it downloads and runs,
// using Clocked's Inspect, Guard and Protect endpoints, and decides whether
// it is safe to run.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Manas-Sehgxl/inspect/internal/clocked"
	"github.com/Manas-Sehgxl/inspect/internal/fetch"
)

type Options struct {
	MaxDepth   int  // how many levels of nested downloads to follow
	MaxScripts int  // cap on scripts inspected per scan
	NoGuard    bool // skip the prompt-injection check
	NoProtect  bool // skip the secrets/PII check
	NoCompare  bool // don't diff against earlier versions with Compare

	// Progress, if set, is called before each slow step.
	Progress func(msg string)
}

// Target is the script to start from. Source is a URL, file path or "-" for
// stdin. Remote targets are downloaded; for the others Body holds the script.
// Page, if set, is the URL or file of the instructions the script came
// from, to check against it.
type Target struct {
	Source string
	Remote bool
	Body   string
	Page   string
}

type Report struct {
	Scripts  []*Script `json:"scripts"`
	Page     *Page     `json:"page,omitempty"`
	Decision Decision  `json:"decision"`
	Credits  float64   `json:"credits"`
}

type Script struct {
	Source    string `json:"source"`
	Parent    string `json:"parent,omitempty"`
	ParentLn  int    `json:"parent_line,omitempty"`
	Depth     int    `json:"depth"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated,omitempty"`
	Body      string `json:"-"`

	Inspect   *clocked.ScriptResult    `json:"inspect,omitempty"`
	Guard     *clocked.InjectionResult `json:"guard,omitempty"`
	Protect   *clocked.PIIResult       `json:"protect,omitempty"`
	Downloads []fetch.Download         `json:"downloads,omitempty"`
	Changed   *Change                  `json:"changed,omitempty"`
	Errors    []string                 `json:"errors,omitempty"`

	Decision Decision `json:"decision"`
	Reasons  []string `json:"reasons,omitempty"`
}

type Scanner struct {
	Client  *clocked.Client
	Opts    Options
	History History // optional; enables "changed since last check"
}

func (s *Scanner) progress(format string, args ...any) {
	if s.Opts.Progress != nil {
		s.Opts.Progress(fmt.Sprintf(format, args...))
	}
}

// Run inspects t and, breadth first, every script it downloads and runs.
// Calls are made one at a time because trial accounts allow a single
// concurrent request.
func (s *Scanner) Run(ctx context.Context, t Target) (*Report, error) {
	root := &Script{Source: t.Source, Body: t.Body}
	if t.Remote {
		s.progress("fetching %s", t.Source)
		body, trunc, err := fetch.Get(ctx, t.Source)
		if err != nil {
			return nil, err
		}
		root.Body, root.Truncated = body, trunc
	} else {
		root.Body, root.Truncated = fetch.Limit(root.Body)
	}

	rep := &Report{}
	seen := map[string]bool{t.Source: true}
	queue := []*Script{root}

	for len(queue) > 0 {
		sc := queue[0]
		queue = queue[1:]
		rep.Scripts = append(rep.Scripts, sc)

		if err := s.analyze(ctx, sc, len(rep.Scripts)); err != nil {
			return nil, err
		}

		for _, d := range sc.Downloads {
			if !d.Executed || d.Dynamic || seen[d.URL] {
				continue
			}
			seen[d.URL] = true
			child := &Script{Source: d.URL, Parent: sc.Source, ParentLn: d.Line, Depth: sc.Depth + 1}
			if child.Depth > s.Opts.MaxDepth || len(rep.Scripts)+len(queue) >= s.Opts.MaxScripts {
				sc.Reasons = append(sc.Reasons, fmt.Sprintf("line %d runs %s, which was not followed (limit reached)", d.Line, d.URL))
				sc.Decision = max(sc.Decision, Warn)
				continue
			}
			s.progress("fetching %s", d.URL)
			body, trunc, err := fetch.Get(ctx, d.URL)
			if err != nil {
				sc.Reasons = append(sc.Reasons, fmt.Sprintf("line %d runs %s, which could not be fetched: %v", d.Line, d.URL, err))
				sc.Decision = max(sc.Decision, Warn)
				continue
			}
			child.Body, child.Truncated = body, trunc
			queue = append(queue, child)
		}
	}

	if t.Page != "" {
		rep.Page = s.checkPage(ctx, t.Page, root)
		rep.Decision = max(rep.Decision, rep.Page.Decision)
	}

	now := time.Now()
	for _, sc := range rep.Scripts {
		rep.Decision = max(rep.Decision, sc.Decision)
		if s.History != nil && sc.Source != "stdin" {
			s.History.Record(Snapshot{Source: sc.Source, SHA256: sc.SHA256, Body: sc.Body, Decision: sc.Decision, CheckedAt: now})
		}
	}
	rep.Credits = s.Client.Credits()
	return rep, nil
}

func (s *Scanner) analyze(ctx context.Context, sc *Script, n int) error {
	sum := sha256.Sum256([]byte(sc.Body))
	sc.SHA256 = hex.EncodeToString(sum[:])
	sc.Downloads = fetch.FindDownloads(sc.Body)

	if strings.TrimSpace(sc.Body) == "" {
		sc.Reasons = append(sc.Reasons, "script is empty")
		sc.Decision = max(sc.Decision, Warn)
		return nil
	}

	s.progress("[%d] Inspect: assessing %s", n, sc.Source)
	res, err := s.Client.Script(ctx, clocked.ScriptRequest{Script: sc.Body})
	if err != nil {
		return fmt.Errorf("inspect %s: %w", sc.Source, err)
	}
	sc.Inspect = res

	if !s.Opts.NoGuard {
		s.progress("[%d] Guard: checking %s for prompt injection", n, sc.Source)
		g, err := s.guard(ctx, sc.Body)
		if err != nil {
			sc.Errors = append(sc.Errors, "guard: "+err.Error())
		}
		sc.Guard = g
	}

	if !s.Opts.NoProtect {
		s.progress("[%d] Protect: looking for secrets in %s", n, sc.Source)
		p, err := s.protect(ctx, sc.Body)
		if err != nil {
			sc.Errors = append(sc.Errors, "protect: "+err.Error())
		}
		sc.Protect = p
	}

	s.diff(ctx, sc, n)
	decide(sc)
	return nil
}
