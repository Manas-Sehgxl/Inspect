package clocked

// Evidence is a passage Clocked points at to justify a judgment. Start and
// End are character offsets into the text that was sent. Inspect returns the
// passage as "line", Guard as "quote".
type Evidence struct {
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
	Evidence         []Evidence         `json:"evidence,omitempty"`
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
	Evidence         []Evidence         `json:"evidence,omitempty"`
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
