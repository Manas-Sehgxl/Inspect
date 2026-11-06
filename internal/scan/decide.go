package scan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Decision is the overall call on a script. Higher is worse.
type Decision int

const (
	Pass Decision = iota
	Warn
	Block
)

func (d Decision) String() string {
	switch d {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	default:
		return "BLOCK"
	}
}

func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.ToLower(d.String()))
}

// decide turns the endpoint results for one script into a decision and the
// reasons behind it. It only raises sc.Decision, never lowers it.
func decide(sc *Script) {
	raise := func(d Decision, format string, args ...any) {
		sc.Decision = max(sc.Decision, d)
		sc.Reasons = append(sc.Reasons, fmt.Sprintf(format, args...))
	}

	if r := sc.Inspect; r != nil {
		thr := r.Threshold
		if thr == 0 {
			thr = 0.5
		}
		switch {
		case r.Verdict == "malicious" || r.Malicious >= thr:
			raise(Block, "Inspect: malicious (%.2f), %s", r.Malicious, r.Category)
		case r.Suspicious >= thr:
			raise(Warn, "Inspect: suspicious (%.2f), %s", r.Suspicious, r.Category)
		}
	}

	// A script that tries to talk an AI reviewer into running it is a red flag
	// on its own, whatever the rest of the code does.
	if g := sc.Guard; g != nil {
		thr := g.Threshold
		if thr == 0 {
			thr = 0.5
		}
		if g.Injection >= thr {
			raise(Block, "Guard: text aimed at AI agents (%.2f), %s", g.Injection, g.Category)
		}
	}

	if p := sc.Protect; p != nil && p.Counts["secret"] > 0 {
		raise(Warn, "Protect: %d hardcoded secret(s) in the script", p.Counts["secret"])
	}

	for _, d := range sc.Downloads {
		if d.Executed && d.Dynamic {
			raise(Warn, "line %d runs code from a URL built at run time (%s), so it could not be checked", d.Line, d.URL)
		}
	}

	if sc.Truncated {
		raise(Warn, "script is longer than 200,000 characters; only the start was inspected")
	}
	for _, e := range sc.Errors {
		raise(Warn, "check failed: %s", e)
	}
}
