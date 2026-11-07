package fetch

import (
	"regexp"
	"strings"
)

// Download is a URL a script fetches.
type Download struct {
	URL  string `json:"url"`
	Line int    `json:"line"` // 1-based line in the script

	// Executed means the script runs what it downloads: it pipes it into a
	// shell, saves it to a file it then runs, or the URL names a script file.
	Executed bool `json:"executed"`

	// Dynamic means the URL is built from shell variables, so we can't fetch
	// it ahead of time.
	Dynamic bool `json:"dynamic"`

	// File is where curl or wget saves the download, if anywhere.
	File string `json:"file,omitempty"`
}

var (
	urlRe      = regexp.MustCompile("https?://[^\\s'\"<>|;()`]+")
	fetcherRe  = regexp.MustCompile(`\b(curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\b`)
	pipeExecRe = regexp.MustCompile(`\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+=\S+\s+)*(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b|\|\s*iex\b|\b(ba|z)?sh\s+(-s\s+)?<\(|\b(ba|z)?sh\s+-c\s+["']?\$\(|\biex\s*\(|Invoke-Expression`)
	scriptExt  = regexp.MustCompile(`\.(sh|bash|zsh|ps1|py|pl|rb)$`)

	// Where curl and wget save a download. curl -O and wget without -O use
	// the URL's file name.
	curlOutRe  = regexp.MustCompile(`\s(?:-[a-zA-Z]*o|--output)[\s=]\s*["']?([^\s"';|&]+)`)
	curlNameRe = regexp.MustCompile(`\s(?:-[a-zA-Z]*O\b|--remote-name\b)`)
	wgetOutRe  = regexp.MustCompile(`\s(?:-[a-zA-Z]*O|--output-document)[\s=]?\s*["']?([^\s"';|&]+)`)
)

// FindDownloads lists the URLs that script fetches with curl, wget or a
// PowerShell equivalent. Comment lines are skipped; lines ending in a
// backslash are joined with the next one first.
func FindDownloads(script string) []Download {
	var out []Download
	seen := map[string]bool{}

	lines := strings.Split(script, "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := lines[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t\r"), "\\") && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t\r"), "\\") + " " + lines[i+1]
			i++
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !fetcherRe.MatchString(line) {
			continue
		}
		piped := pipeExecRe.MatchString(line)
		urls := urlRe.FindAllString(line, -1)
		for _, u := range urls {
			u = strings.TrimRight(u, ".,")
			if seen[u] {
				continue
			}
			seen[u] = true
			d := Download{
				URL:      u,
				Line:     lineNo,
				Executed: piped || scriptExt.MatchString(urlPath(u)),
				Dynamic:  strings.Contains(u, "$"),
			}
			if len(urls) == 1 { // with several URLs, which one goes to the file is unclear
				d.File = outputFile(line, u)
			}
			out = append(out, d)
		}
	}

	// A download saved to a file and then run, as in
	//   curl -fsSL https://get.docker.com -o get-docker.sh
	//   sudo sh ./get-docker.sh
	for i, d := range out {
		if !d.Executed && d.File != "" && runsFile(script, d.File) {
			out[i].Executed = true
		}
	}
	return out
}

// outputFile returns the file a curl or wget line saves url to, or "" when
// it writes to stdout.
func outputFile(line, url string) string {
	var f string
	switch {
	case strings.Contains(line, "curl"):
		if m := curlOutRe.FindStringSubmatch(line); m != nil {
			f = m[1]
		} else if curlNameRe.MatchString(line) {
			f = pathBase(url)
		}
	case strings.Contains(line, "wget"):
		if m := wgetOutRe.FindStringSubmatch(line); m != nil {
			f = m[1]
		} else if !strings.Contains(line, "|") {
			f = pathBase(url)
		}
	}
	if f == "-" || f == "/dev/null" {
		return ""
	}
	return f
}

func pathBase(u string) string {
	p := urlPath(u)
	if i := strings.LastIndex(p, "/"); i >= 0 && i > len("https://") {
		return p[i+1:]
	}
	return ""
}

// runsFile reports whether script runs file: through a shell (sh file,
// sudo bash ./file), by sourcing it (source file, . file) or directly
// (./file). Merely touching it, as in chmod +x file, doesn't count.
func runsFile(script, file string) bool {
	name := regexp.QuoteMeta(strings.TrimPrefix(file, "./"))
	re := regexp.MustCompile(`(?m)(?:^|[\s;&|(])(?:` +
		`(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh|source|\.)\s+(?:-\S+\s+)*["']?(?:\./)?` + name +
		`|(?:sudo\s+)?["']?\./` + name +
		`)["']?(?:\s|$|[;&|)])`)
	return re.MatchString(script)
}

func urlPath(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}
