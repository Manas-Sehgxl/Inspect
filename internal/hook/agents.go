package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// Agent adapts the checker to one coding agent's pre-execution hook. Each
// agent sends the shell command in its own JSON shape and expects its own
// answer, but the decision underneath is always Checker.Check.
type Agent struct {
	Name     string
	Settings string // where the config snippet goes
	Notes    string // anything the user should know about this agent

	// read returns the command and working directory, or ok=false when the
	// call isn't a shell command.
	read func(data []byte) (command, cwd string, ok bool, err error)

	// write answers the agent and returns the exit status to use.
	write func(w io.Writer, v Verdict) (int, error)

	config func(binary string) string
}

// Agents lists the supported agents by the name used on the command line.
var Agents = map[string]*Agent{
	"claude-code": {
		Name:     "Claude Code",
		Settings: "~/.claude/settings.json, or .claude/settings.local.json in a project",
		read:     readToolInput("Bash"),
		write:    writeClaude,
		config:   func(bin string) string { return toolHookConfig("PreToolUse", "Bash", bin+" hook claude-code", 120) },
	},
	"codex": {
		Name:     "OpenAI Codex",
		Settings: "~/.codex/hooks.json, or .codex/hooks.json in a project (then trust it with /hooks)",
		Notes:    "Codex can't ask you from a hook yet, so WARN is treated like BLOCK and the agent is told to show you the findings.",
		read:     readToolInput("Bash"),
		write:    writeCodex,
		config:   func(bin string) string { return toolHookConfig("PreToolUse", "Bash", bin+" hook codex", 120) },
	},
	"gemini": {
		Name:     "Gemini CLI",
		Settings: "~/.gemini/settings.json, or .gemini/settings.json in a project",
		Notes:    "Gemini CLI hooks can only allow or deny, so WARN is treated like BLOCK.",
		read:     readToolInput("run_shell_command"),
		write:    writeGemini,
		// Gemini CLI's timeout is in milliseconds.
		config: func(bin string) string {
			return toolHookConfig("BeforeTool", "run_shell_command", bin+" hook gemini", 120_000)
		},
	},
	"cursor": {
		Name:     "Cursor",
		Settings: "~/.cursor/hooks.json, or .cursor/hooks.json in a project (restart Cursor after)",
		read:     readCursor,
		write:    writeCursor,
		config:   cursorConfig,
	},
}

// AgentNames returns the supported agent names, sorted.
func AgentNames() []string {
	names := make([]string, 0, len(Agents))
	for n := range Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Config is the settings snippet that installs the hook for this agent.
func (a *Agent) Config(binary string) string { return a.config(binary) }

// Run answers one hook call: it reads the agent's request from in, checks
// the command and writes the agent's answer to out. It returns the exit
// status the hook process should use.
func (a *Agent) Run(ctx context.Context, in io.Reader, out io.Writer, c *Checker) (int, error) {
	data, err := io.ReadAll(io.LimitReader(in, 4<<20))
	if err != nil {
		return 1, err
	}
	command, cwd, ok, err := a.read(data)
	if err != nil {
		return 1, fmt.Errorf("reading %s hook input: %w", a.Name, err)
	}
	var v Verdict
	if ok {
		v = c.Check(ctx, command, cwd)
	}
	return a.write(out, v)
}

// readToolInput reads the {tool_name, tool_input: {command}, cwd} shape that
// Claude Code, Codex and Gemini CLI share.
func readToolInput(tool string) func([]byte) (string, string, bool, error) {
	return func(data []byte) (string, string, bool, error) {
		var req struct {
			ToolName  string `json:"tool_name"`
			ToolInput struct {
				Command string `json:"command"`
			} `json:"tool_input"`
			Cwd string `json:"cwd"`
		}
		if err := json.Unmarshal(data, &req); err != nil {
			return "", "", false, err
		}
		if req.ToolName != tool || req.ToolInput.Command == "" {
			return "", "", false, nil
		}
		return req.ToolInput.Command, req.Cwd, true, nil
	}
}

func readCursor(data []byte) (string, string, bool, error) {
	var req struct {
		Command string `json:"command"`
		Cwd     string `json:"cwd"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return "", "", false, err
	}
	return req.Command, req.Cwd, req.Command != "", nil
}

// toolSpecific is the hookSpecificOutput object Claude Code and Codex use.
type toolSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

type toolOutput struct {
	SystemMessage      string       `json:"systemMessage,omitempty"`
	HookSpecificOutput toolSpecific `json:"hookSpecificOutput"`
}

const blockedNote = "\nDo not try to run this script another way. Tell the user what inspect found."

const cantAskNote = "\nThis agent can't ask the user from a hook, so inspect stopped the command. " +
	"Show the user these findings; if they still want it, they can run the command themselves."

func writeJSON(w io.Writer, v any) (int, error) {
	return 0, json.NewEncoder(w).Encode(v)
}

func writeClaude(w io.Writer, v Verdict) (int, error) {
	if !v.Ran {
		return 0, nil // no opinion: Claude Code's own permissions apply
	}
	out := toolOutput{SystemMessage: v.Summary, HookSpecificOutput: toolSpecific{HookEventName: "PreToolUse"}}
	switch v.Decision {
	case scan.Block:
		out.HookSpecificOutput.PermissionDecision = "deny"
		out.HookSpecificOutput.PermissionDecisionReason = v.Summary + blockedNote
	case scan.Warn:
		out.HookSpecificOutput.PermissionDecision = "ask"
		out.HookSpecificOutput.PermissionDecisionReason = v.Summary
	default:
		out.HookSpecificOutput.AdditionalContext = v.Summary
	}
	return writeJSON(w, out)
}

func writeCodex(w io.Writer, v Verdict) (int, error) {
	if !v.Ran {
		return 0, nil
	}
	out := toolOutput{SystemMessage: v.Summary, HookSpecificOutput: toolSpecific{HookEventName: "PreToolUse"}}
	switch v.Decision {
	case scan.Block:
		out.HookSpecificOutput.PermissionDecision = "deny"
		out.HookSpecificOutput.PermissionDecisionReason = v.Summary + blockedNote
	case scan.Warn:
		// Codex parses "ask" but doesn't support it yet: it would mark the
		// hook as failed and run the command anyway.
		out.HookSpecificOutput.PermissionDecision = "deny"
		out.HookSpecificOutput.PermissionDecisionReason = v.Summary + cantAskNote
	default:
		out.HookSpecificOutput.AdditionalContext = v.Summary
	}
	return writeJSON(w, out)
}

func writeGemini(w io.Writer, v Verdict) (int, error) {
	if !v.Ran {
		return 0, nil
	}
	type geminiOutput struct {
		Decision      string `json:"decision,omitempty"`
		Reason        string `json:"reason,omitempty"`
		SystemMessage string `json:"systemMessage,omitempty"`
	}
	out := geminiOutput{SystemMessage: v.Summary}
	switch v.Decision {
	case scan.Block:
		out.Decision, out.Reason = "deny", v.Summary+blockedNote
	case scan.Warn:
		out.Decision, out.Reason = "deny", v.Summary+cantAskNote
	}
	return writeJSON(w, out)
}

func writeCursor(w io.Writer, v Verdict) (int, error) {
	// Cursor blocks the command on empty or invalid output, so every call
	// gets an answer, even "allow" for commands that run no script.
	type cursorOutput struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message,omitempty"`
		AgentMessage string `json:"agent_message,omitempty"`
	}
	out := cursorOutput{Permission: "allow"}
	if v.Ran {
		out.UserMessage, out.AgentMessage = v.Summary, v.Summary
		switch v.Decision {
		case scan.Block:
			out.Permission = "deny"
			out.AgentMessage += blockedNote
		case scan.Warn:
			out.Permission = "ask"
		}
	}
	return writeJSON(w, out)
}

// toolHookConfig is the shared {"hooks": {event: [{matcher, hooks}]}} shape
// of Claude Code, Codex and Gemini CLI settings.
func toolHookConfig(event, matcher, command string, timeout int) string {
	handler := map[string]any{"type": "command", "command": command, "timeout": timeout}
	if event == "BeforeTool" {
		handler["name"] = "inspect" // Gemini CLI labels hooks by name
	} else {
		handler["statusMessage"] = "inspect: checking script with Clocked"
	}
	cfg := map[string]any{
		"hooks": map[string]any{
			event: []any{map[string]any{"matcher": matcher, "hooks": []any{handler}}},
		},
	}
	return mustIndent(cfg)
}

func cursorConfig(bin string) string {
	return mustIndent(map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"beforeShellExecution": []any{map[string]any{
				"command": bin + " hook cursor",
				"timeout": 120,
			}},
		},
	})
}

func mustIndent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b)) + "\n"
}
