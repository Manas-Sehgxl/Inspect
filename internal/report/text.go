// Package report prints a scan.Report for people (Text) or programs (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Manas-Sehgxl/inspect/internal/clocked"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

func JSON(w io.Writer, rep *scan.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

type printer struct {
	w     io.Writer
	color bool
}

func (p printer) paint(code, s string) string {
	if !p.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p printer) dim(s string) string  { return p.paint("2", s) }
func (p printer) bold(s string) string { return p.paint("1", s) }

func (p printer) decision(d scan.Decision) string {
	switch d {
	case scan.Pass:
		return p.paint("1;32", " PASS ")
	case scan.Warn:
		return p.paint("1;30;43", " WARN ")
	default:
		return p.paint("1;37;41", " BLOCK ")
	}
}

func (p printer) f(format string, args ...any) { fmt.Fprintf(p.w, format, args...) }

// Text writes a human-readable report.
func Text(w io.Writer, rep *scan.Report, color bool) {
	p := printer{w, color}

	if len(rep.Scripts) > 1 {
		p.f("%s\n", p.bold("Script tree"))
		for _, sc := range rep.Scripts {
			indent := strings.Repeat("   ", sc.Depth)
			if sc.Depth == 0 {
				p.f("  %s\n", sc.Source)
			} else {
				p.f("  %s└─ %s %s\n", indent[3:], sc.Source, p.dim(fmt.Sprintf("(run by line %d of its parent)", sc.ParentLn)))
			}
		}
		p.f("\n")
	}

	for _, sc := range rep.Scripts {
		p.script(sc)
	}
	if rep.Page != nil {
		p.page(rep.Page, rep.Scripts[0].Body)
	}

	p.f("%s %s  %s\n", p.bold("Decision"), p.decision(rep.Decision), advice(rep.Decision))
	p.f("%s\n", p.dim(fmt.Sprintf("Clocked credits used: %g", rep.Credits)))
}

func advice(d scan.Decision) string {
	switch d {
	case scan.Pass:
		return "no risks found"
	case scan.Warn:
		return "read the flagged lines before running this"
	default:
		return "don't run this"
	}
}

func (p printer) script(sc *scan.Script) {
	p.f("%s  %s\n", p.bold(sc.Source), p.decision(sc.Decision))
	p.f("  %s\n", p.dim(fmt.Sprintf("sha256 %s · %d lines", sc.SHA256[:16], strings.Count(strings.TrimSuffix(sc.Body, "\n"), "\n")+1)))

	if r := sc.Inspect; r != nil {
		parts := []string{fmt.Sprintf("%s (malicious %.2f, suspicious %.2f)", r.Verdict, r.Malicious, r.Suspicious)}
		if r.Category != "" {
			parts = append(parts, r.Category)
		}
		if r.Severity != "" {
			parts = append(parts, r.Severity)
		}
		p.f("  %-10s %s\n", "Inspect", strings.Join(parts, " · "))
		for _, e := range r.Evidence {
			p.evidence(sc.Body, e.Start, e.Text(), "")
		}
	}

	if g := sc.Guard; g != nil {
		if g.Injection >= threshold(g.Threshold) {
			p.f("  %-10s %s (%.2f) · %s\n", "Guard", p.paint("31", "injection aimed at AI agents"), g.Injection, g.Category)
			for _, e := range g.Evidence {
				p.evidence(sc.Body, e.Start, e.Text(), "")
			}
		} else {
			p.f("  %-10s no prompt injection (%.2f)\n", "Guard", g.Injection)
		}
	}

	if pr := sc.Protect; pr != nil {
		if len(pr.Entities) == 0 {
			p.f("  %-10s no secrets, IPs or emails\n", "Protect")
		} else {
			p.f("  %-10s %s\n", "Protect", counts(pr.Counts))
			for _, e := range pr.Entities {
				p.evidence(sc.Body, e.Start, e.Value, fmt.Sprintf("%-10s %s", e.Type, displayValue(e)))
			}
		}
	}

	if n := len(sc.Downloads); n > 0 {
		run := 0
		for _, d := range sc.Downloads {
			if d.Executed {
				run++
			}
		}
		p.f("  %-10s %d found, %d run as code\n", "Downloads", n, run)
		for _, d := range sc.Downloads {
			tag := "fetch"
			if d.Executed {
				tag = "run"
			}
			p.f("  %s %s %s\n", p.dim(fmt.Sprintf("%8d │", d.Line)), p.dim(fmt.Sprintf("%-5s", tag)), d.URL)
		}
	}

	if ch := sc.Changed; ch != nil {
		p.f("  %-10s %s\n", "Changed", p.paint("33", changeLine(ch)))
		for _, c := range ch.Conflicts() {
			was, now := diffLines(c, ch.PrevBody, sc.Body)
			for _, l := range was {
				p.f("  %s %s\n", p.dim("         │"), p.paint("31", "- "+shorten(strings.TrimSpace(l), 96)))
			}
			for _, l := range now {
				p.evidence(sc.Body, -1, l, p.paint("32", "+ "+shorten(strings.TrimSpace(l), 96)))
			}
		}
	}

	p.reasons(sc.Reasons)
	p.f("\n")
}

// diffLines narrows one Compare conflict to the old and new lines that
// differ. If nothing differs line by line (a reworded passage), it falls
// back to the first line of each quote.
func diffLines(c clocked.CompareFinding, oldBody, newBody string) (was, now []string) {
	was = scan.ChangedLines(c.A.Quote, newBody)
	now = scan.ChangedLines(c.B.Quote, oldBody)
	if len(was) == 0 && len(now) == 0 {
		first := func(s string) string { l, _, _ := strings.Cut(strings.TrimSpace(s), "\n"); return l }
		return []string{first(c.A.Quote)}, []string{first(c.B.Quote)}
	}
	return was, now
}

func changeLine(ch *scan.Change) string {
	s := fmt.Sprintf("since you checked it %s (it was %s) · +%d −%d lines",
		ch.Since.Local().Format("Jan 2 15:04"), ch.PrevDecision, ch.Added, ch.Removed)
	switch {
	case ch.Note != "":
		s += " · " + ch.Note
	case ch.Compare != nil && len(ch.Compare.Pairs) > 0:
		pr := ch.Compare.Pairs[0]
		s += fmt.Sprintf(" · Compare: %s", pr.Relation)
		if n := len(pr.Conflicts); n > 0 {
			s += fmt.Sprintf(", %d behaviour change(s)", n)
		}
	}
	return s
}

func (p printer) reasons(rs []string) {
	if len(rs) == 0 {
		return
	}
	p.f("  %s\n", "Why")
	for _, r := range rs {
		p.f("    • %s\n", r)
	}
}

// page prints the install-page check. script is the root script's body,
// which Verify's evidence offsets point into.
func (p printer) page(pg *scan.Page, script string) {
	p.f("%s  %s\n", p.bold("Install page "+pg.Source), p.decision(pg.Decision))
	if g := pg.Guard; g != nil {
		if g.Injection >= threshold(g.Threshold) {
			p.f("  %-10s %s (%.2f) · %s\n", "Guard", p.paint("31", "text aimed at AI agents"), g.Injection, g.Category)
			for _, e := range g.Evidence {
				p.f("  %s %s\n", p.dim("         │"), p.paint("33", shorten(strings.TrimSpace(e.Text()), 100)))
			}
		} else {
			p.f("  %-10s no prompt injection (%.2f)\n", "Guard", g.Injection)
		}
	}
	if v := pg.Verify; v != nil {
		counted := 0
		for _, c := range v.Claims {
			if c.Counted {
				counted++
			}
		}
		bad := pg.Contradicted()
		if len(bad) == 0 {
			p.f("  %-10s %d claim(s) about the script checked, none contradicted\n", "Verify", counted)
		} else {
			p.f("  %-10s %s\n", "Verify", p.paint("31", fmt.Sprintf("%d of %d claim(s) contradicted by the script", len(bad), counted)))
		}
		for _, c := range bad {
			p.f("  %s %s\n", p.dim("    page │"), fmt.Sprintf("%q", shorten(strings.TrimSpace(c.Claim), 90)))
			for _, e := range c.Evidence {
				p.evidence(script, e.Start, e.Quote, "")
			}
		}
		if len(bad) > 0 {
			p.f("  %s\n", p.dim("           (the lines Inspect flagged in the script are listed above)"))
		}
	}
	p.reasons(pg.Reasons)
	p.f("\n")
}

// evidence prints one flagged passage with its line number. If label is
// empty the passage itself is shown.
func (p printer) evidence(body string, start int, text, label string) {
	line := LineOf(body, start, text)
	if label == "" {
		label = shorten(strings.TrimSpace(text), 100)
	}
	num := "       ?"
	if line > 0 {
		num = fmt.Sprintf("%8d", line)
	}
	p.f("  %s %s\n", p.dim(num+" │"), p.paint("33", label))
}

// LineOf returns the 1-based line holding the passage text, which Clocked
// says starts at character offset start. If the offset doesn't match the
// text (offsets are in characters, Go strings in bytes) it searches instead.
// It returns 0 if the passage can't be found.
func LineOf(body string, start int, text string) int {
	if start >= 0 && start <= utf8.RuneCountInString(body) {
		prefix := string([]rune(body)[:start])
		if text == "" || strings.HasPrefix(body[len(prefix):], text) {
			return strings.Count(prefix, "\n") + 1
		}
	}
	if text != "" {
		if i := strings.Index(body, text); i >= 0 {
			return strings.Count(body[:i], "\n") + 1
		}
	}
	return 0
}

func threshold(t float64) float64 {
	if t == 0 {
		return 0.5
	}
	return t
}

func counts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%d %s", m[k], strings.ReplaceAll(k, "_", " "))
	}
	return strings.Join(parts, " · ")
}

// displayValue hides most of a secret so the report itself can be shared.
func displayValue(e clocked.PIIEntity) string {
	if e.Type != "secret" {
		return e.Value
	}
	r := []rune(e.Value)
	if len(r) <= 4 {
		return strings.Repeat("•", len(r))
	}
	return string(r[:4]) + strings.Repeat("•", min(len(r)-4, 12))
}

func shorten(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
