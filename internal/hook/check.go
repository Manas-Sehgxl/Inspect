package hook

import (
	"context"
	"fmt"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/fetch"
	"github.com/Manas-Sehgxl/inspect/internal/report"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// Verdict is the result of checking one shell command.
type Verdict struct {
	Ran      bool // the command runs at least one script, so it was checked
	Decision scan.Decision
	Summary  string
}

// Checker decides whether a shell command is safe to run. Every agent
// adapter shares it.
type Checker struct {
	// NewScanner is only called once there is something to check, so
	// ordinary commands never need an API key or the network.
	NewScanner func() (*scan.Scanner, error)
	Cache      *Cache
}

// Check finds the scripts command would run and checks each one. Failures
// to check become Warn, so a person decides instead of the hook guessing.
func (c *Checker) Check(ctx context.Context, command, cwd string) Verdict {
	found := Find(command, cwd)
	if len(found) == 0 {
		return Verdict{}
	}

	v := Verdict{Ran: true}
	var parts []string
	warn := func(msg string) {
		v.Decision = max(v.Decision, scan.Warn)
		parts = append(parts, "inspect WARN: "+msg)
	}

	var sc *scan.Scanner
	for _, f := range found {
		if f.Dynamic {
			warn(fmt.Sprintf("the command runs code from %s, a URL built at run time, so it can't be checked", f.Source))
			continue
		}
		body := f.Body
		if f.Remote {
			b, trunc, err := fetch.Get(ctx, f.Source)
			if err != nil {
				warn(fmt.Sprintf("could not fetch %s to check it: %v", f.Source, err))
				continue
			}
			if trunc {
				warn(fmt.Sprintf("%s is over 200,000 characters; only the start was checked", f.Source))
			}
			body = b
		}

		if d, s, ok := c.Cache.Get(body); ok {
			v.Decision = max(v.Decision, d)
			parts = append(parts, s+" (cached)")
			continue
		}

		if sc == nil {
			var err error
			if sc, err = c.NewScanner(); err != nil {
				warn(fmt.Sprintf("can't check %s: %v", f.Source, err))
				continue
			}
		}
		rep, err := sc.Run(ctx, scan.Target{Source: f.Source, Body: body})
		if err != nil {
			warn(fmt.Sprintf("checking %s failed: %v", f.Source, err))
			continue
		}
		s := report.Summary(rep)
		c.Cache.Put(body, rep, s)
		v.Decision = max(v.Decision, rep.Decision)
		parts = append(parts, s)
	}
	v.Summary = strings.Join(parts, "\n\n")
	return v
}
