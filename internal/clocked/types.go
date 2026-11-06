package clocked

import (
	"bytes"
	"encoding/json"
)

// Evidence is a passage Clocked points at to justify a judgment. Start and
// End are character offsets into the text that was sent. Inspect returns the
// passage as "line", the others as "quote". Document names the source
// document when the request had several.
type Evidence struct {
	Document   string  `json:"document,omitempty"`
	Line       string  `json:"line,omitempty"`
	Quote      string  `json:"quote,omitempty"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

func (e Evidence) Text() string {
	if e.Line != "" {
		return e.Line
	}
	return e.Quote
}

// EvidenceList is a list of passages. Clocked has sent evidence as an array,
// a single object and an object keyed by document, so all three are read; an
// unknown shape is dropped rather than failing the whole check.
type EvidenceList []Evidence

func (l *EvidenceList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	*l = nil
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case '[':
		var a []Evidence
		if json.Unmarshal(b, &a) == nil {
			*l = a
		}
	case '{':
		var one Evidence
		if json.Unmarshal(b, &one) == nil && one.Text() != "" {
			*l = EvidenceList{one}
			return nil
		}
		var byDoc map[string]json.RawMessage
		if json.Unmarshal(b, &byDoc) != nil {
			return nil
		}
		for doc, raw := range byDoc {
			var sub EvidenceList
			if json.Unmarshal(raw, &sub) != nil {
				continue
			}
			for i := range sub {
				if sub[i].Document == "" {
					sub[i].Document = doc
				}
			}
			*l = append(*l, sub...)
		}
	}
	return nil
}

// ScriptRequest is the body for POST /script (Inspect).
type ScriptRequest struct {
	Script       string   `json:"script"`
	Instructions string   `json:"instructions,omitempty"`
	Threshold    *float64 `json:"threshold,omitempty"`
}

type ScriptResult struct {
	Model            string             `json:"model"`
	Malicious        float64            `json:"malicious"`
	Suspicious       float64            `json:"suspicious"`
	Verdict          string             `json:"verdict"`
	Threshold        float64            `json:"threshold"`
	Category         string             `json:"category"`
	Categories       map[string]float64 `json:"categories,omitempty"`
	Severity         string             `json:"severity,omitempty"`
	Severities       map[string]float64 `json:"severities,omitempty"`
	SeverityExpected *float64           `json:"severity_expected,omitempty"`
	Evidence         EvidenceList       `json:"evidence,omitempty"`
}

// InjectionRequest is the body for POST /injection (Guard). Source is "user"
// for a direct message or "content" for retrieved text such as a web page
// or a downloaded script.
type InjectionRequest struct {
	Text         string   `json:"text"`
	Source       string   `json:"source,omitempty"`
	Instructions string   `json:"instructions,omitempty"`
	Threshold    *float64 `json:"threshold,omitempty"`
}

type InjectionResult struct {
	Model            string             `json:"model"`
	Injection        float64            `json:"injection"`
	Verdict          string             `json:"verdict"`
	Threshold        float64            `json:"threshold"`
	Source           string             `json:"source"`
	Category         string             `json:"category"`
	Categories       map[string]float64 `json:"categories,omitempty"`
	Severity         string             `json:"severity,omitempty"`
	SeverityExpected *float64           `json:"severity_expected,omitempty"`
	Evidence         EvidenceList       `json:"evidence,omitempty"`
}

// PIIRequest is the body for POST /pii (Protect). Entities maps each kind to
// nil (a built-in kind) or a description (a custom kind).
type PIIRequest struct {
	Text      string         `json:"text"`
	Entities  map[string]any `json:"entities,omitempty"`
	Threshold *float64       `json:"threshold,omitempty"`
	Anonymize any            `json:"anonymize,omitempty"`
	MaskKeep  int            `json:"mask_keep,omitempty"`
}

type PIIEntity struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}

type PIIResult struct {
	Model          string         `json:"model"`
	Entities       []PIIEntity    `json:"entities"`
	Counts         map[string]int `json:"counts,omitempty"`
	AnonymizedText string         `json:"anonymized_text,omitempty"`
}

// Document is one named source text for Compare and Verify.
type Document struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// CompareRequest is the body for POST /compare.
type CompareRequest struct {
	Documents    []Document `json:"documents"`
	Instructions string     `json:"instructions,omitempty"`
	Evidence     string     `json:"evidence,omitempty"` // "all", "flagged" or "none"
}

type CompareResult struct {
	Model   string        `json:"model"`
	Verdict string        `json:"verdict"`
	Pairs   []ComparePair `json:"pairs"`
}

type ComparePair struct {
	A             string             `json:"a"`
	B             string             `json:"b"`
	Relation      string             `json:"relation"` // same, overlapping, conflicting or unrelated
	Related       float64            `json:"related"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Duplicates    []CompareFinding   `json:"duplicates,omitempty"`
	Conflicts     []CompareFinding   `json:"conflicts,omitempty"`
}

// CompareFinding pairs a passage in document A with the matching passage
// in document B.
type CompareFinding struct {
	Kind       string   `json:"kind"`
	Confidence float64  `json:"confidence"`
	A          Evidence `json:"a"`
	B          Evidence `json:"b"`
}

// GroundingRequest is the body for POST /grounding (Verify). Answer is the
// text whose claims are checked against Documents.
type GroundingRequest struct {
	Documents    []Document `json:"documents"`
	Answer       string     `json:"answer"`
	Question     string     `json:"question,omitempty"`
	Instructions string     `json:"instructions,omitempty"`
	Evidence     string     `json:"evidence,omitempty"` // "all", "flagged" or "none"
}

type GroundingResult struct {
	Model      string  `json:"model"`
	Grounded   float64 `json:"grounded"`
	Ungrounded float64 `json:"ungrounded"`
	Verdict    string  `json:"verdict"`
	Threshold  float64 `json:"threshold"`
	Claims     []Claim `json:"claims"`
}

type Claim struct {
	Claim        string       `json:"claim"`
	Kind         string       `json:"kind,omitempty"`
	Counted      bool         `json:"counted"`
	Supported    float64      `json:"supported"`
	Contradicted float64      `json:"contradicted"`
	NotStated    float64      `json:"not_stated"`
	NotAClaim    float64      `json:"not_a_claim"`
	Verdict      string       `json:"verdict"`
	Evidence     EvidenceList `json:"evidence,omitempty"`
}
