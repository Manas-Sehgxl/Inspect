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
	"strings"

	"github.com/Manas-Sehgxl/inspect/internal/clocked"
	"github.com/Manas-Sehgxl/inspect/internal/report"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

const usage = `inspect checks a script with Clocked before you run it.

Usage:
  inspect check <url|file|->       print a risk report
  inspect run   <url|file|-> [-- args...]
                                   check, ask, then run the exact bytes checked
  curl -fsSL <url> | inspect run   same, reading the script from stdin

Flags:
  --json          print the report as JSON (check only)
  --depth N       levels of nested downloads to follow (default 2)
  --no-guard      skip the prompt-injection check
  --no-protect    skip the secrets check
  --force         let run execute a script that was blocked

Exit status: 0 pass, 1 warn, 2 block, 3 error.
Set CLOCKED_API_KEY to your key from https://clocked.rezolve.ai/account.
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
	force := fs.Bool("force", false, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}

	key := os.Getenv("CLOCKED_API_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "inspect: set CLOCKED_API_KEY (create a key at https://clocked.rezolve.ai/account)")
		return exitError
	}

	target, err := readTarget(pos)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := clocked.New(key)
	if u := os.Getenv("CLOCKED_BASE_URL"); u != "" {
		client.BaseURL = u
	}
	sc := &scan.Scanner{
		Client: client,
		Opts: scan.Options{
			MaxDepth:   *depth,
			MaxScripts: 8,
			NoGuard:    *noGuard,
			NoProtect:  *noProtect,
			Progress:   progress(),
		},
	}
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
