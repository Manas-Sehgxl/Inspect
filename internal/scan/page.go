package scan

import (
	"context"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/clocked"
	"github.com/Manas-Sehgxl/inspect/internal/fetch"
)

// Page is the check of the install page or README a script came from.
type Page struct {
	Source string                   `json:"source"`
	Text   string                   `json:"-"`
	Guard  *clocked.InjectionResult `json:"guard,omitempty"`
	Verify *clocked.GroundingResult `json:"verify,omitempty"`
	Errors []string                 `json:"errors,omitempty"`

	Decision Decision `json:"decision"`
	Reasons  []string `json:"reasons,omitempty"`
}

// Contradicted returns the page's claims that the script contradicts.
func (p *Page) Contradicted() []clocked.Claim {
	if p == nil || p.Verify == nil {
		return nil
	}
	var out []clocked.Claim
	for _, c := range p.Verify.Claims {
		if c.Verdict == "contradicted" || c.Contradicted >= 0.5 {
			out = append(out, c)
		}
	}
	return out
}

// verifyChars is Verify's limit on the answer, which here is the page text.
const verifyChars = 20_000

const verifyInstructions = `The answer is text from the web page or README that tells users to run an install script. The document is that script's source code.
Treat statements about what the script or installer does, needs or leaves alone as claims: where it installs, whether it needs root or sudo, what it downloads, what files or settings it changes, what data it sends, how to uninstall it.
Judge each claim against the code only. Marketing text, feature descriptions of the product itself and instructions to the reader are not claims about the script.`

// checkPage reads the page, checks it for text aimed at AI agents and checks
// its claims about the script against the script itself.
func (s *Scanner) checkPage(ctx context.Context, source string, root *Script) *Page {
	p := &Page{Source: source}
	text, err := readPage(ctx, source)
	if err != nil {
		p.Errors = append(p.Errors, err.Error())
		p.Decision = Warn
		p.Reasons = append(p.Reasons, "could not read the page: "+err.Error())
		return p
	}
	p.Text = excerpt(text, root.Source, verifyChars)

	if !s.Opts.NoGuard {
		s.progress("Guard: checking %s for text aimed at AI agents", source)
		g, err := s.guard(ctx, p.Text)
		if err != nil {
			p.Errors = append(p.Errors, "guard: "+err.Error())
		}
		p.Guard = g
	}

	s.progress("Verify: checking what %s says against the script", source)
	script, _ := fetch.Limit(root.Body)
	if r := []rune(script); len(r) > 150_000 {
		script = string(r[:150_000]) // stay inside Verify's token budget
	}
	v, err := s.Client.Grounding(ctx, clocked.GroundingRequest{
		Documents:    []clocked.Document{{ID: "script", Text: script}},
		Answer:       p.Text,
		Question:     "What does this install script do to the user's system?",
		Instructions: verifyInstructions,
		Evidence:     "flagged",
	})
	if err != nil {
		p.Errors = append(p.Errors, "verify: "+err.Error())
	}
	p.Verify = v

	decidePage(p)
	return p
}

func decidePage(p *Page) {
	if g := p.Guard; g != nil && g.Injection >= threshold(g.Threshold) {
		p.Decision = max(p.Decision, Block)
		p.Reasons = append(p.Reasons, fmt.Sprintf("Guard: the page has text aimed at AI agents (%.2f), %s", g.Injection, g.Category))
	}
	for _, c := range p.Contradicted() {
		p.Decision = max(p.Decision, Warn)
		p.Reasons = append(p.Reasons, fmt.Sprintf("Verify: the page says %q, but the script contradicts it", strings.TrimSpace(c.Claim)))
	}
	for _, e := range p.Errors {
		p.Decision = max(p.Decision, Warn)
		p.Reasons = append(p.Reasons, "check failed: "+e)
	}
}

func threshold(t float64) float64 {
	if t == 0 {
		return 0.5
	}
	return t
}

func readPage(ctx context.Context, source string) (string, error) {
	var raw string
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		body, err := fetch.Page(ctx, source)
		if err != nil {
			return "", err
		}
		raw = body
	} else {
		data, err := os.ReadFile(source)
		if err != nil {
			return "", err
		}
		raw = string(data)
	}
	if looksHTML(raw) {
		raw = HTMLText(raw)
	}
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("%s has no text", source)
	}
	return raw, nil
}

func looksHTML(s string) bool {
	head := strings.ToLower(s[:min(len(s), 1024)])
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html") || strings.Contains(head, "<body")
}

var (
	dropRe  = regexp.MustCompile(`(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)>`)
	blockRe = regexp.MustCompile(`(?i)<(br|/p|/div|/li|/h[1-6]|/tr|/pre|/section|/article)\b[^>]*>`)
	tagRe   = regexp.MustCompile(`<[^>]*>`)
	spaceRe = regexp.MustCompile(`[ \t\r\f\v]+`)
	blankRe = regexp.MustCompile(`\n\s*\n+`)
)

// HTMLText turns a web page into plain text. It is deliberately simple: it
// drops scripts and styles, keeps line breaks at the ends of blocks and
// removes the remaining tags. HTML comments are kept as text, because text
// hidden from human readers is where injections aimed at agents tend to go,
// and Guard needs to see it.
func HTMLText(page string) string {
	page = strings.ReplaceAll(page, "<!--", "\n")
	page = strings.ReplaceAll(page, "-->", "\n")
	page = dropRe.ReplaceAllString(page, " ")
	page = blockRe.ReplaceAllString(page, "\n")
	page = tagRe.ReplaceAllString(page, " ")
	page = html.UnescapeString(page)
	page = spaceRe.ReplaceAllString(page, " ")
	page = blankRe.ReplaceAllString(page, "\n\n")
	return strings.TrimSpace(page)
}

// excerpt returns up to n characters of text, centred on the first mention
// of the script's URL when the page has one, since that is where the page
// talks about the script.
func excerpt(text, scriptURL string, n int) string {
	r := []rune(text)
	if len(r) <= n {
		return text
	}
	start := 0
	if i := strings.Index(text, scriptURL); i >= 0 && scriptURL != "" {
		at := len([]rune(text[:i]))
		start = max(0, min(at-n/2, len(r)-n))
	}
	return string(r[start : start+n])
}
