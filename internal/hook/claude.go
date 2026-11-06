package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/fetch"
	"github.com/Manas-Sehgxl/inspect/internal/report"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// claudeInput is the part of Claude Code's PreToolUse payload we read.
type claudeInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
	Cwd string `json:"cwd"`
}

type claudeOutput struct {
	SystemMessage      string         `json:"systemMessage,omitempty"`
	HookSpecificOutput claudeSpecific `json:"hookSpecificOutput"`
}

type claudeSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

// ClaudeConfig is the settings.json snippet that installs the hook.
func ClaudeConfig(binary string) string {
	return fmt.Sprintf(`{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": %q,
            "timeout": 120,
            "statusMessage": "inspect: checking script with Clocked"
          }
        ]
      }
    ]
  }
}
`, binary+" hook claude-code")
}

// Claude answers one Claude Code PreToolUse call. Commands that run no
// script produce no output, so Claude Code's normal permission flow applies.
// newScanner is only called once there is something to check.
func Claude(ctx context.Context, in io.Reader, out io.Writer, newScanner func() (*scan.Scanner, error), cache *Cache) error {
	var req claudeInput
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		return fmt.Errorf("reading hook input: %w", err)
	}
	if req.ToolName != "Bash" || req.ToolInput.Command == "" {
		return nil
	}
	found := Find(req.ToolInput.Command, req.Cwd)
	if len(found) == 0 {
		return nil
	}

	decision, summary := check(ctx, found, newScanner, cache)
	resp := claudeOutput{
		SystemMessage:      summary,
		HookSpecificOutput: claudeSpecific{HookEventName: "PreToolUse"},
	}
	switch decision {
	case scan.Block:
		resp.HookSpecificOutput.PermissionDecision = "deny"
		resp.HookSpecificOutput.PermissionDecisionReason = summary +
			"\nDo not try to run this script another way. Tell the user what inspect found."
	case scan.Warn:
		resp.HookSpecificOutput.PermissionDecision = "ask"
		resp.HookSpecificOutput.PermissionDecisionReason = summary
	default:
		resp.HookSpecificOutput.AdditionalContext = summary
	}
	return json.NewEncoder(out).Encode(resp)
}

// check scans every script found and returns the worst decision with a
// summary of each. Failures to check become Warn, so a person decides.
func check(ctx context.Context, found []Found, newScanner func() (*scan.Scanner, error), cache *Cache) (scan.Decision, string) {
	var worst scan.Decision
	var parts []string
	warn := func(msg string) {
		worst = max(worst, scan.Warn)
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

		if d, s, ok := cache.Get(body); ok {
			worst = max(worst, d)
			parts = append(parts, s+" (cached)")
			continue
		}

		if sc == nil {
			var err error
			if sc, err = newScanner(); err != nil {
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
		cache.Put(body, rep, s)
		worst = max(worst, rep.Decision)
		parts = append(parts, s)
	}
	return worst, strings.Join(parts, "\n\n")
}
