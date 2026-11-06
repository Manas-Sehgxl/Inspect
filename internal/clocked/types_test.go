package clocked

import (
	"encoding/json"
	"testing"
)

func TestEvidenceListShapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"array", `{"evidence":[{"quote":"a","start":1},{"quote":"b"}]}`, 2},
		{"null", `{"evidence":null}`, 0},
		{"missing", `{}`, 0},
		{"single object", `{"evidence":{"quote":"a","start":3}}`, 1},
		{"by document", `{"evidence":{"script-1":[{"quote":"a"}],"script-2":[{"quote":"b"},{"quote":"c"}]}}`, 3},
		{"unknown shape", `{"evidence":"oops"}`, 0},
	}
	for _, tt := range tests {
		var c Claim
		if err := json.Unmarshal([]byte(tt.in), &c); err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if len(c.Evidence) != tt.want {
			t.Errorf("%s: %d passages, want %d", tt.name, len(c.Evidence), tt.want)
		}
	}

	var c Claim
	json.Unmarshal([]byte(`{"evidence":{"script-2":[{"quote":"b"}]}}`), &c)
	if c.Evidence[0].Document != "script-2" {
		t.Errorf("document not filled in from key: %+v", c.Evidence[0])
	}
}
