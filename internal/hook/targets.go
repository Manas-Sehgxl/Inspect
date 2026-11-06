// Package hook lets coding agents check scripts before they run them. It
// finds the scripts a shell command would execute and answers the agent's
// pre-tool-use hook with allow, ask or deny.
package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/fetch"
)

// Found is a script a command would run.
type Found struct {
	Source  string // URL, or absolute path for local files
	Remote  bool
	Dynamic bool   // URL built from shell variables; can't be fetched ahead
	Body    string // file contents, for local scripts
}

var (
	segmentSep = regexp.MustCompile(`&&|\|\||[;|&\n]`)
	shells     = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "source": true, ".": true}
	prefixes   = map[string]bool{"sudo": true, "env": true, "exec": true, "time": true, "nohup": true, "command": true}
)

// Find lists the scripts command would run: remote scripts piped or fed
// into an interpreter, and local script files run directly or through a
// shell. Relative paths resolve against cwd. It does no network I/O.
func Find(command, cwd string) []Found {
	var out []Found
	for _, d := range fetch.FindDownloads(command) {
		if d.Executed {
			out = append(out, Found{Source: d.URL, Remote: true, Dynamic: d.Dynamic})
		}
	}

	seen := map[string]bool{}
	for _, seg := range segmentSep.Split(command, -1) {
		path, explicit := scriptArg(strings.Fields(seg))
		if path == "" {
			continue
		}
		path = resolve(path, cwd)
		if seen[path] {
			continue
		}
		body, ok := readScript(path, explicit)
		if !ok {
			continue
		}
		seen[path] = true
		out = append(out, Found{Source: path, Body: body})
	}
	return out
}

// scriptArg returns the script file a simple command runs. explicit is true
// when a shell is named (`bash x`), so any text file counts; for `./x` the
// file must have a shell #! line.
func scriptArg(tokens []string) (path string, explicit bool) {
	// Skip sudo, its flags, env, VAR=value and the like.
	i := 0
	for i < len(tokens) && isPrefix(unquote(tokens[i])) {
		i++
	}
	if i >= len(tokens) {
		return "", false
	}

	cmd := unquote(tokens[i])
	if shells[filepath.Base(cmd)] {
		for _, t := range tokens[i+1:] {
			t = unquote(t)
			if t == "-c" || t == "-s" || strings.HasPrefix(t, "<") {
				return "", false // inline code or stdin, not a file
			}
			if !strings.HasPrefix(t, "-") {
				return t, true
			}
		}
		return "", false
	}
	if strings.HasPrefix(cmd, "./") || strings.HasPrefix(cmd, "../") || strings.HasPrefix(cmd, "/") || strings.HasPrefix(cmd, "~/") {
		return cmd, false
	}
	return "", false
}

func isPrefix(t string) bool {
	if prefixes[t] || strings.HasPrefix(t, "-") {
		return true
	}
	name, _, ok := strings.Cut(t, "=")
	return ok && name != "" && !strings.ContainsAny(name, "/.")
}

func unquote(s string) string {
	return strings.Trim(s, `"'`)
}

func resolve(path, cwd string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	if !filepath.IsAbs(path) && cwd != "" {
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

// readScript reads path if it is a text file small enough to inspect. With
// explicit false it must also start with a #! line naming a shell, which
// skips binaries and scripts in other languages.
func readScript(path string, explicit bool) (string, bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4*fetch.MaxChars {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(data[:min(len(data), 8192)], 0) >= 0 {
		return "", false
	}
	if !explicit {
		first, _, _ := bytes.Cut(data, []byte("\n"))
		if !bytes.HasPrefix(first, []byte("#!")) || !bytes.Contains(first, []byte("sh")) {
			return "", false
		}
	}
	return string(data), true
}
