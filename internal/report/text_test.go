package report

import "testing"

func TestLineOf(t *testing.T) {
	body := "#!/bin/sh\necho héllo\nrm -rf /tmp/x\n"
	tests := []struct {
		name  string
		start int
		text  string
		want  int
	}{
		{"offset in characters", 21, "rm -rf /tmp/x", 3},
		{"wrong offset falls back to search", 2, "rm -rf /tmp/x", 3},
		{"first line", 0, "#!/bin/sh", 1},
		{"not found", 999, "curl evil", 0},
	}
	for _, tt := range tests {
		if got := LineOf(body, tt.start, tt.text); got != tt.want {
			t.Errorf("%s: LineOf(%d, %q) = %d, want %d", tt.name, tt.start, tt.text, got, tt.want)
		}
	}
}
