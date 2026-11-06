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
		if got[i] != want[i] {
			t.Errorf("download %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}
