package report

import (
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// View is a compact, display-ready form of a report for the browser
// extension: line numbers are resolved and secrets are already masked.
type View struct {
	Decision scan.Decision `json:"decision"`
	Scripts  []ScriptView  `json:"scripts"`
	Page     *PageView     `json:"page,omitempty"`
	Credits  float64       `json:"credits"`
}

type ScriptView struct {
	Source   string        `json:"source"`
	Depth    int           `json:"depth"`
	Decision scan.Decision `json:"decision"`
	Verdict  string        `json:"verdict,omitempty"`
	Category string        `json:"category,omitempty"`
	Reasons  []string      `json:"reasons,omitempty"`
	Flagged  []Flag        `json:"flagged,omitempty"`
	Changes  []string      `json:"changes,omitempty"` // "- old" / "+ new" lines
}

// Flag is one line a check pointed at.
type Flag struct {
	Line int    `json:"line,omitempty"`
	Text string `json:"text"`
	By   string `json:"by"` // Inspect, Guard or Protect
}

type PageView struct {
	Decision scan.Decision `json:"decision"`
	Reasons  []string      `json:"reasons,omitempty"`
	Guard    []string      `json:"guard,omitempty"` // passages aimed at AI agents
}

func NewView(rep *scan.Report) View {
	v := View{Decision: rep.Decision, Credits: rep.Credits}
	for _, sc := range rep.Scripts {
		sv := ScriptView{Source: sc.Source, Depth: sc.Depth, Decision: sc.Decision, Reasons: sc.Reasons}
		flag := func(start int, text, by string) {
			sv.Flagged = append(sv.Flagged, Flag{Line: LineOf(sc.Body, start, text), Text: shorten(strings.TrimSpace(text), 160), By: by})
		}
		if r := sc.Inspect; r != nil {
			sv.Verdict, sv.Category = r.Verdict, r.Category
			for _, e := range r.Evidence {
				flag(e.Start, e.Text(), "Inspect")
			}
		}
		if g := sc.Guard; g != nil && g.Injection >= threshold(g.Threshold) {
			for _, e := range g.Evidence {
				flag(e.Start, e.Text(), "Guard")
			}
		}
		if p := sc.Protect; p != nil {
			for _, e := range p.Entities {
				sv.Flagged = append(sv.Flagged, Flag{Line: LineOf(sc.Body, e.Start, e.Value), Text: e.Type + ": " + displayValue(e), By: "Protect"})
			}
		}
		if ch := sc.Changed; ch != nil {
			sv.Changes = append(sv.Changes, "changed "+changeLine(ch))
			for _, c := range ch.Conflicts() {
				was, now := diffLines(c, ch.PrevBody, sc.Body)
				for _, l := range was {
					sv.Changes = append(sv.Changes, "- "+strings.TrimSpace(l))
				}
				for _, l := range now {
					sv.Changes = append(sv.Changes, "+ "+strings.TrimSpace(l))
				}
			}
		}
		v.Scripts = append(v.Scripts, sv)
	}
	if pg := rep.Page; pg != nil {
		pv := &PageView{Decision: pg.Decision, Reasons: pg.Reasons}
		if g := pg.Guard; g != nil && g.Injection >= threshold(g.Threshold) {
			for _, e := range g.Evidence {
				pv.Guard = append(pv.Guard, shorten(strings.TrimSpace(e.Text()), 160))
			}
		}
		v.Page = pv
	}
	return v
}
