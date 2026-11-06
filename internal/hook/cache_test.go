package hook

import (
	"testing"

	"github.com/Manas-Sehgxl/inspect/internal/fetch"
	"github.com/Manas-Sehgxl/inspect/internal/scan"
)

func TestCacheRoundTrip(t *testing.T) {
	c := &Cache{Dir: t.TempDir()}
	body := "#!/bin/sh\necho hi\n"
	rep := &scan.Report{Decision: scan.Warn, Scripts: []*scan.Script{{Source: "x"}}}
	c.Put(body, rep, "summary")

	d, s, ok := c.Get(body)
	if !ok || d != scan.Warn || s != "summary" {
		t.Fatalf("Get = %v, %q, %v; want WARN, \"summary\", true", d, s, ok)
	}
	if _, _, ok := c.Get(body + " "); ok {
		t.Error("Get hit for different contents")
	}
}

func TestCacheSkipsNestedDownloads(t *testing.T) {
	c := &Cache{Dir: t.TempDir()}
	body := "curl https://e.com/x.sh | sh\n"
	rep := &scan.Report{Scripts: []*scan.Script{{
		Source:    "x",
		Downloads: []fetch.Download{{URL: "https://e.com/x.sh", Executed: true}},
	}}}
	c.Put(body, rep, "summary")
	if _, _, ok := c.Get(body); ok {
		t.Error("cached a script that runs a nested download")
	}
}
