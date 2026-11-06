package report

import (
	"fmt"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// maxSummaryEvidence caps the flagged lines quoted per script, so a summary
// stays short enough for an agent hook message.
const maxSummaryEvidence = 4

// Summary is a short plain-text report, for agent hooks and notifications.
func Summary(rep *scan.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "inspect %s: %s", rep.Decision, rep.Scripts[0].Source)
	for _, sc := range rep.Scripts {
		if sc.Depth > 0 {
			fmt.Fprintf(&b, "\n%s (run by line %d of %s): %s", sc.Source, sc.ParentLn, sc.Parent, sc.Decision)
		}
		for _, r := range sc.Reasons {
			fmt.Fprintf(&b, "\n- %s", r)
		}
		if sc.Changed != nil {
			fmt.Fprintf(&b, "\n- changed %s", changeLine(sc.Changed))
			for i, c := range sc.Changed.Conflicts() {
				if i == maxSummaryEvidence {
					break
				}
				was, now := diffLines(c, sc.Changed.PrevBody, sc.Body)
				for _, l := range was {
					fmt.Fprintf(&b, "\n  - %s", shorten(strings.TrimSpace(l), 90))
				}
				for _, l := range now {
					fmt.Fprintf(&b, "\n  + %s", shorten(strings.TrimSpace(l), 90))
				}
			}
		}

		n := 0
		quote := func(start int, text string) {
			if n >= maxSummaryEvidence {
				return
			}
			n++
			if line := LineOf(sc.Body, start, text); line > 0 {
				fmt.Fprintf(&b, "\n  line %d: %s", line, shorten(strings.TrimSpace(text), 100))
			} else {
				fmt.Fprintf(&b, "\n  %s", shorten(strings.TrimSpace(text), 100))
			}
		}
		if sc.Decision == scan.Pass {
			continue
		}
		if g := sc.Guard; g != nil && g.Injection >= threshold(g.Threshold) {
			for _, e := range g.Evidence {
				quote(e.Start, e.Text())
			}
		}
		if r := sc.Inspect; r != nil {
			for _, e := range r.Evidence {
				quote(e.Start, e.Text())
			}
		}
	}
	if pg := rep.Page; pg != nil {
		fmt.Fprintf(&b, "\nInstall page %s: %s", pg.Source, pg.Decision)
		for _, r := range pg.Reasons {
			fmt.Fprintf(&b, "\n- %s", r)
		}
	}
	if rep.Decision == scan.Pass {
		fmt.Fprintf(&b, "\n- no risks found by Inspect, Guard or Protect")
	}
	return b.String()
}
