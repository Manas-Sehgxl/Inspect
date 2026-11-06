package hook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFind(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("install.sh", "echo hi\n")             // no #! line
	write("setup", "#!/bin/bash\necho hi\n")     // shell script without extension
	write("tool.py", "#!/usr/bin/env python3\n") // not a shell script
	write("bin", "\x7fELF\x00\x00")

	tests := []struct {
		command string
		want    []string // sources, in order
	}{
		{"ls -la", nil},
		{"go test ./...", nil},
		{"curl -fsSL https://get.example.com/i.sh | sh", []string{"https://get.example.com/i.sh"}},
		{"cd /tmp && curl -o x https://e.com/x && bash install.sh", []string{dir + "/install.sh"}},
		{"sudo -E bash ./install.sh --yes", []string{dir + "/install.sh"}},
		{"FOO=1 ./setup", []string{dir + "/setup"}},
		{"./install.sh", nil}, // no #! line, so only an explicit shell counts
		{"./tool.py", nil},
		{"bash bin", nil},
		{"bash -c 'echo hi'", nil},
		{"source setup; ./setup", []string{dir + "/setup"}},
		{"bash missing.sh", nil},
	}
	for _, tt := range tests {
		got := Find(tt.command, dir)
		var srcs []string
		for _, f := range got {
			srcs = append(srcs, f.Source)
		}
		if len(srcs) != len(tt.want) {
			t.Errorf("Find(%q) = %v, want %v", tt.command, srcs, tt.want)
			continue
		}
		for i := range srcs {
			if srcs[i] != tt.want[i] {
				t.Errorf("Find(%q) = %v, want %v", tt.command, srcs, tt.want)
			}
		}
	}
}
