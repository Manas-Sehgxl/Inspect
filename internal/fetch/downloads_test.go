package fetch

import "testing"

func TestFindDownloads(t *testing.T) {
	script := `#!/bin/sh
# curl https://docs.example.com/should-be-skipped.sh | sh
curl -fsSL https://get.example.com/stage2.sh | sudo bash
wget -qO- https://example.com/data.tar.gz -O /tmp/data.tar.gz
sh -c "$(curl -fsSL https://raw.example.com/install)"
curl -fsSL "https://dl.example.com/${VERSION}/tool" \
  | bash -s -- --yes
echo "visit https://example.com for docs"
`
	got := FindDownloads(script)
	want := []Download{
		{URL: "https://get.example.com/stage2.sh", Line: 3, Executed: true},
		{URL: "https://example.com/data.tar.gz", Line: 4},
		{URL: "https://raw.example.com/install", Line: 5, Executed: true},
		{URL: "https://dl.example.com/${VERSION}/tool", Line: 6, Executed: true, Dynamic: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d downloads, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		got[i].File = "" // covered by TestDownloadThenRun
		if got[i] != want[i] {
			t.Errorf("download %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestDownloadThenRun(t *testing.T) {
	tests := []struct {
		script string
		run    bool
	}{
		// Docker's documented convenience-script install.
		{"curl -fsSL https://get.docker.com -o get-docker.sh\nsudo sh ./get-docker.sh --dry-run", true},
		{"curl -fsSLo install https://e.com/install && chmod +x install && ./install", true},
		{"curl -O https://e.com/dl/setup && bash setup", true},
		{"wget -O /tmp/x https://e.com/x; source /tmp/x", true},
		{"wget https://e.com/bootstrap\n. bootstrap", true},
		{"curl -o data.json https://e.com/data\ncat data.json", false},
		{"curl -o tool https://e.com/tool\nchmod +x tool\nrm tool", false},
		{"curl -fsSL https://e.com/x -o x\nsh ./other", false},
	}
	for _, tt := range tests {
		d := FindDownloads(tt.script)
		if len(d) != 1 {
			t.Fatalf("%q: %d downloads", tt.script, len(d))
		}
		if d[0].Executed != tt.run {
			t.Errorf("%q: executed = %v, want %v (file %q)", tt.script, d[0].Executed, tt.run, d[0].File)
		}
	}
}
