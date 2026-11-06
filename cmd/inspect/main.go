// Command inspect checks shell scripts and curl | bash installers with
// Clocked before you run them.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/clocked"
	"github.com/Manas-Sehgxl/inspect/internal/hook"
	"github.com/Manas-Sehgxl/inspect/internal/report"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
	"github.com/Manas-Sehgxl/inspect/internal/serve"
)

const usage = `inspect checks a script with Clocked before you run it.

Usage:
  inspect check <url|file|->       print a risk report
  inspect run   <url|file|-> [-- args...]
                                   check, ask, then run the exact bytes checked
  curl -fsSL <url> | inspect run   same, reading the script from stdin
  inspect hook <agent>             pre-execution hook for a coding agent; agents:
                                   claude-code, codex, gemini, cursor
  inspect hook <agent> --print-config
                                   print the config snippet that installs it
  inspect hook exec <command>      agent-neutral check: exit 2 means block
  inspect serve                    local server for the browser extension

Flags:
  --page URL|FILE the install page or README the command came from; its
                  claims are checked against the script
  --json          print the report as JSON (check only)
  --depth N       levels of nested downloads to follow (default 2)
  --no-guard      skip the prompt-injection check
  --no-protect    skip the secrets check
  --no-compare    don't diff against the last version you checked
  --force         let run execute a script that was blocked

Exit status: 0 pass, 1 warn, 2 block, 3 error.
The Clocked API key comes from CLOCKED_API_KEY, or else ~/.config/clocked/key.
Create one at https://clocked.rezolve.ai/account.
`

// Exit codes, so scripts and agent hooks can act on the decision.
const (
	exitPass  = 0
	exitWarn  = 1
	exitBlock = 2
	exitError = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return exitPass
	}
	cmd, args := args[0], args[1:]
	if cmd == "hook" {
		return runHook(args)
	}
	if cmd == "serve" {
		return runServe(args)
	}
	if cmd != "check" && cmd != "run" {
		// `inspect <url>` is short for `inspect check <url>`.
		cmd, args = "check", append([]string{cmd}, args...)
	}

	// Everything after "--" is passed to the script by `run`.
	var scriptArgs []string
	for i, a := range args {
		if a == "--" {
			args, scriptArgs = args[:i], args[i+1:]
			break
		}
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	jsonOut := fs.Bool("json", false, "")
	depth := fs.Int("depth", 2, "")
	noGuard := fs.Bool("no-guard", false, "")
	noProtect := fs.Bool("no-protect", false, "")
	noCompare := fs.Bool("no-compare", false, "")
	page := fs.String("page", "", "")
	force := fs.Bool("force", false, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}

	opts := scan.Options{
		MaxDepth:   *depth,
		MaxScripts: 8,
		NoGuard:    *noGuard,
		NoProtect:  *noProtect,
		NoCompare:  *noCompare,
		Progress:   progress(),
	}
	sc, err := newScanner(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}

	target, err := readTarget(pos)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}
	target.Page = *page

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rep, err := sc.Run(ctx, target)
	clearProgress()
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}

	if *jsonOut && cmd == "check" {
		report.JSON(os.Stdout, rep)
	} else {
		report.Text(os.Stdout, rep, colorOK(os.Stdout))
	}

	if cmd == "check" {
		return exitCode(rep.Decision)
	}
	return execute(rep, scriptArgs, *force)
}

func runHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "inspect: usage: inspect hook <%s|exec> [--print-config]\n", strings.Join(hook.AgentNames(), "|"))
		return exitError
	}
	name, args := args[0], args[1:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	checker := &hook.Checker{
		NewScanner: func() (*scan.Scanner, error) { return newScanner(scan.Options{MaxDepth: 2, MaxScripts: 8}) },
		Cache:      hook.DefaultCache(),
	}

	if name == "exec" {
		return hookExec(ctx, checker, args)
	}
	agent, ok := hook.Agents[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "inspect: unknown agent %q; supported: %s, or exec for anything else\n", name, strings.Join(hook.AgentNames(), ", "))
		return exitError
	}
	if len(args) > 0 && args[0] == "--print-config" {
		bin, err := os.Executable()
		if err != nil {
			bin = "inspect"
		}
		fmt.Fprintf(os.Stderr, "# %s: merge this into %s\n", agent.Name, agent.Settings)
		if agent.Notes != "" {
			fmt.Fprintf(os.Stderr, "# %s\n", agent.Notes)
		}
		fmt.Print(agent.Config(bin))
		return exitPass
	}

	code, err := agent.Run(ctx, os.Stdin, os.Stdout, checker)
	if err != nil {
		// Exit 1 is a non-blocking error for every supported agent: it is
		// reported and the agent carries on, so a broken hook can't wedge it.
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return 1
	}
	return code
}

// hookExec is the agent-neutral hook: the command comes as arguments or on
// stdin, the summary goes to stderr and the exit status carries the
// decision. Exit 2 means block, which is what most agents' hooks expect.
func hookExec(ctx context.Context, checker *hook.Checker, args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	command := strings.Join(args, " ")
	if command == "" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			fmt.Fprintln(os.Stderr, "inspect:", err)
			return exitError
		}
		command = string(data)
	}
	cwd, _ := os.Getwd()
	v := checker.Check(ctx, command, cwd)
	if !v.Ran {
		return exitPass
	}
	fmt.Fprintln(os.Stderr, v.Summary)
	return exitCode(v.Decision)
}

// runServe starts the local server the browser extension talks to.
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := fs.Int("port", serve.DefaultPort, "")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if _, err := apiKey(); err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}
	token, err := serve.LoadToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect: pairing token:", err)
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	s := &serve.Server{
		Port:       *port,
		Token:      token,
		NewScanner: func() (*scan.Scanner, error) { return newScanner(scan.Options{MaxDepth: 2, MaxScripts: 8}) },
	}
	fmt.Fprintf(os.Stderr, "inspect is listening on http://127.0.0.1:%d for the browser extension.\n", *port)
	fmt.Fprintf(os.Stderr, "Pairing token (paste it into the extension once): %s\n", token)
	if err := s.ListenAndServe(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}
	return exitPass
}

func newScanner(opts scan.Options) (*scan.Scanner, error) {
	key, err := apiKey()
	if err != nil {
		return nil, err
	}
	client := clocked.New(key)
	if u := os.Getenv("CLOCKED_BASE_URL"); u != "" {
		client.BaseURL = u
	}
	return &scan.Scanner{Client: client, Opts: opts, History: scan.DefaultHistory()}, nil
}

// apiKey reads the Clocked key from CLOCKED_API_KEY, or else from
// ~/.config/clocked/key. The file matters for hooks, which don't inherit
// variables exported in the user's shell.
func apiKey() (string, error) {
	if k := os.Getenv("CLOCKED_API_KEY"); k != "" {
		return k, nil
	}
	if dir, err := os.UserConfigDir(); err == nil {
		if data, err := os.ReadFile(filepath.Join(dir, "clocked", "key")); err == nil {
			if k := strings.TrimSpace(string(data)); k != "" {
				return k, nil
			}
		}
	}
	return "", errors.New("no Clocked API key: set CLOCKED_API_KEY or write it to ~/.config/clocked/key (create one at https://clocked.rezolve.ai/account)")
}

// parseInterspersed lets flags come after the target, as in
// `inspect check URL --json`. The flag package stops at the first argument.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func readTarget(pos []string) (scan.Target, error) {
	src := "-"
	if len(pos) > 0 {
		src = pos[0]
	}
	if len(pos) > 1 {
		return scan.Target{}, fmt.Errorf("one target at a time (got %d); pass script arguments after --", len(pos))
	}

	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return scan.Target{Source: src, Remote: true}, nil
	}

	var data []byte
	var err error
	if src == "-" {
		if isTerminal(os.Stdin) {
			return scan.Target{}, errors.New("no script given; pass a URL or file, or pipe a script in")
		}
		data, err = io.ReadAll(os.Stdin)
		src = "stdin"
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return scan.Target{}, err
	}
	return scan.Target{Source: src, Body: string(data)}, nil
}

func exitCode(d scan.Decision) int {
	switch d {
	case scan.Pass:
		return exitPass
	case scan.Warn:
		return exitWarn
	default:
		return exitBlock
	}
}

// execute asks for confirmation and runs the root script. It runs the bytes
// that were inspected, never a fresh download, so the server can't swap the
// script between the check and the run.
func execute(rep *scan.Report, args []string, force bool) int {
	root := rep.Scripts[0]
	if rep.Decision == scan.Block && !force {
		fmt.Fprintln(os.Stderr, "inspect: refusing to run a blocked script (use --force to override)")
		return exitBlock
	}

	// When the script came in on stdin, stdin is the pipe, so prompts and the
	// script itself read from the terminal instead.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect: no terminal to confirm on; not running")
		return exitError
	}
	defer tty.Close()

	prompt := "Run it? [y/N] "
	if rep.Decision == scan.Block {
		prompt = "This script was BLOCKED. Type 'run anyway' to run it: "
	}
	fmt.Fprint(tty, prompt)
	answer, _ := bufio.NewReader(tty).ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	ok := answer == "y" || answer == "yes"
	if rep.Decision == scan.Block {
		ok = answer == "run anyway"
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "inspect: not running")
		return exitCode(rep.Decision)
	}

	f, err := os.CreateTemp("", "inspect-*.sh")
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(root.Body); err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}
	f.Close()

	interp := interpreter(root.Body)
	cmd := exec.Command(interp[0], append(append(interp[1:], f.Name()), args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if !isTerminal(os.Stdin) {
		cmd.Stdin = tty
	}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}
	return exitPass
}

// interpreter picks the program named in the script's #! line, defaulting to
// bash like `curl | bash` would.
func interpreter(body string) []string {
	first, _, _ := strings.Cut(body, "\n")
	if !strings.HasPrefix(first, "#!") {
		return []string{"bash"}
	}
	fields := strings.Fields(strings.TrimPrefix(first, "#!"))
	if len(fields) == 0 {
		return []string{"bash"}
	}
	if strings.HasSuffix(fields[0], "/env") && len(fields) > 1 {
		fields = fields[1:]
		if fields[0] == "-S" && len(fields) > 1 {
			fields = fields[1:]
		}
	}
	return fields
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func colorOK(f *os.File) bool {
	return os.Getenv("NO_COLOR") == "" && isTerminal(f)
}

// progress returns a status-line printer for stderr, or nil when stderr
// isn't a terminal.
func progress() func(string) {
	if !isTerminal(os.Stderr) {
		return nil
	}
	return func(msg string) {
		fmt.Fprintf(os.Stderr, "\r\x1b[2K\x1b[2m%s…\x1b[0m", msg)
	}
}

func clearProgress() {
	if isTerminal(os.Stderr) {
		fmt.Fprint(os.Stderr, "\r\x1b[2K")
	}
}
