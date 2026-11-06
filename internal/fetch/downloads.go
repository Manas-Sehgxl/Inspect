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
	// shell, or the URL names a script file.
	Executed bool `json:"executed"`

	// Dynamic means the URL is built from shell variables, so we can't fetch
	// it ahead of time.
	Dynamic bool `json:"dynamic"`
}

var (
	urlRe      = regexp.MustCompile("https?://[^\\s'\"<>|;()`]+")
	fetcherRe  = regexp.MustCompile(`\b(curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\b`)
	pipeExecRe = regexp.MustCompile(`\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+=\S+\s+)*(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b|\|\s*iex\b|\b(ba|z)?sh\s+(-s\s+)?<\(|\b(ba|z)?sh\s+-c\s+["']?\$\(|\biex\s*\(|Invoke-Expression`)
	scriptExt  = regexp.MustCompile(`\.(sh|bash|zsh|ps1|py|pl|rb)$`)
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
		for _, u := range urlRe.FindAllString(line, -1) {
			u = strings.TrimRight(u, ".,")
			if seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, Download{
				URL:      u,
				Line:     lineNo,
				Executed: piped || scriptExt.MatchString(urlPath(u)),
				Dynamic:  strings.Contains(u, "$"),
			})
		}
	}
	return out
}

func urlPath(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}
