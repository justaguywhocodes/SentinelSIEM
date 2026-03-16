package cases

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIsValidStatus(t *testing.T) {
	valid := []string{"new", "in_progress", "resolved", "closed"}
	for _, s := range valid {
		if !IsValidStatus(s) {
			t.Errorf("expected %q to be valid status", s)
		}
	}

	invalid := []string{"", "pending", "open", "NEW"}
	for _, s := range invalid {
		if IsValidStatus(s) {
			t.Errorf("expected %q to be invalid status", s)
		}
	}
}

func TestIsValidSeverity(t *testing.T) {
	valid := []string{"critical", "high", "medium", "low"}
	for _, s := range valid {
		if !IsValidSeverity(s) {
			t.Errorf("expected %q to be valid severity", s)
		}
	}

	if IsValidSeverity("info") {
		t.Error("expected 'info' to be invalid severity")
	}
}

func TestIsValidResolution(t *testing.T) {
	valid := []string{"true_positive", "false_positive", "benign", "duplicate"}
	for _, r := range valid {
		if !IsValidResolution(r) {
			t.Errorf("expected %q to be valid resolution", r)
		}
	}

	if IsValidResolution("unknown") {
		t.Error("expected 'unknown' to be invalid resolution")
	}
}

func TestIsValidObservableType(t *testing.T) {
	valid := []string{"ip", "hash", "domain", "user", "process", "ja3", "ja4", "community_id", "sni"}
	for _, o := range valid {
		if !IsValidObservableType(o) {
			t.Errorf("expected %q to be valid observable type", o)
		}
	}

	if IsValidObservableType("url") {
		t.Error("expected 'url' to be invalid observable type")
	}
}

func TestCanTransition(t *testing.T) {
	// Forward transitions should be allowed.
	allowed := [][2]string{
		{"new", "in_progress"},
		{"new", "resolved"},
		{"new", "closed"},
		{"in_progress", "resolved"},
		{"in_progress", "closed"},
		{"resolved", "closed"},
	}
	for _, pair := range allowed {
		if !CanTransition(pair[0], pair[1]) {
			t.Errorf("expected transition %s → %s to be allowed", pair[0], pair[1])
		}
	}

	// Reopen transitions should be allowed.
	reopens := [][2]string{
		{"resolved", "in_progress"},
		{"closed", "in_progress"},
	}
	for _, pair := range reopens {
		if !CanTransition(pair[0], pair[1]) {
			t.Errorf("expected reopen %s → %s to be allowed", pair[0], pair[1])
		}
	}

	// Same-status transition should not be allowed.
	for _, s := range []string{"new", "in_progress", "resolved", "closed"} {
		if CanTransition(s, s) {
			t.Errorf("expected same-status transition %s → %s to be disallowed", s, s)
		}
	}

	// Backward transitions (other than reopen) should not be allowed.
	disallowed := [][2]string{
		{"in_progress", "new"},
		{"resolved", "new"},
		{"closed", "new"},
		{"closed", "resolved"},
	}
	for _, pair := range disallowed {
		if CanTransition(pair[0], pair[1]) {
			t.Errorf("expected transition %s → %s to be disallowed", pair[0], pair[1])
		}
	}

	// Invalid statuses should not be allowed.
	if CanTransition("unknown", "new") {
		t.Error("expected invalid status to be disallowed")
	}
	if CanTransition("new", "unknown") {
		t.Error("expected invalid target status to be disallowed")
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") {
		t.Error("critical should outrank high")
	}
	if SeverityRank("high") <= SeverityRank("medium") {
		t.Error("high should outrank medium")
	}
	if SeverityRank("medium") <= SeverityRank("low") {
		t.Error("medium should outrank low")
	}
	if SeverityRank("unknown") != 0 {
		t.Error("unknown severity should return 0")
	}
}

func TestHighestSeverity(t *testing.T) {
	tests := []struct {
		input    []string
		expected string
	}{
		{[]string{"low", "high", "medium"}, "high"},
		{[]string{"critical"}, "critical"},
		{[]string{"low", "low"}, "low"},
		{[]string{"medium", "critical", "high"}, "critical"},
		{[]string{}, "low"},
		{nil, "low"},
	}

	for _, tc := range tests {
		got := HighestSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("HighestSeverity(%v) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestCaseRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	closedAt := now.Add(time.Hour)

	original := Case{
		ID:       "case-001",
		Title:    "Credential Theft — user jsmith on HOST-042",
		Status:   StatusResolved,
		Severity: SeverityHigh,
		Assignee: "analyst1",
		AlertIDs: []string{"alert-001", "alert-002"},
		Observables: []Observable{
			{Type: ObservableIP, Value: "192.168.1.100", Source: "alert-001", Tags: []string{"internal"}},
			{Type: ObservableHash, Value: "abc123def456", Source: "alert-002"},
		},
		Timeline: []TimelineEntry{
			{
				Timestamp:  now,
				Author:     "analyst1",
				ActionType: ActionEscalation,
				Content:    json.RawMessage(`{"alert_ids":["alert-001","alert-002"]}`),
			},
			{
				Timestamp:  now.Add(30 * time.Minute),
				Author:     "analyst1",
				ActionType: ActionComment,
				Content:    json.RawMessage(`{"text":"Investigating lateral movement."}`),
			},
		},
		Tags:       []string{"attack.credential_access", "attack.t1003"},
		Resolution: &Resolution{Type: ResolutionTruePositive, Notes: "Confirmed credential theft."},
		CreatedAt:  now,
		UpdatedAt:  now.Add(time.Hour),
		ClosedAt:   &closedAt,
	}

	// Marshal.
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal.
	var decoded Case
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify fields.
	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Title != original.Title {
		t.Errorf("Title: got %q, want %q", decoded.Title, original.Title)
	}
	if decoded.Status != original.Status {
		t.Errorf("Status: got %q, want %q", decoded.Status, original.Status)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity: got %q, want %q", decoded.Severity, original.Severity)
	}
	if decoded.Assignee != original.Assignee {
		t.Errorf("Assignee: got %q, want %q", decoded.Assignee, original.Assignee)
	}
	if len(decoded.AlertIDs) != len(original.AlertIDs) {
		t.Errorf("AlertIDs length: got %d, want %d", len(decoded.AlertIDs), len(original.AlertIDs))
	}
	if len(decoded.Observables) != len(original.Observables) {
		t.Errorf("Observables length: got %d, want %d", len(decoded.Observables), len(original.Observables))
	}
	if len(decoded.Timeline) != len(original.Timeline) {
		t.Errorf("Timeline length: got %d, want %d", len(decoded.Timeline), len(original.Timeline))
	}
	if len(decoded.Tags) != len(original.Tags) {
		t.Errorf("Tags length: got %d, want %d", len(decoded.Tags), len(original.Tags))
	}
	if decoded.Resolution == nil {
		t.Fatal("Resolution should not be nil")
	}
	if decoded.Resolution.Type != original.Resolution.Type {
		t.Errorf("Resolution.Type: got %q, want %q", decoded.Resolution.Type, original.Resolution.Type)
	}
	if decoded.ClosedAt == nil {
		t.Fatal("ClosedAt should not be nil")
	}

	// Verify observable details.
	if decoded.Observables[0].Type != ObservableIP {
		t.Errorf("Observable[0].Type: got %q, want %q", decoded.Observables[0].Type, ObservableIP)
	}
	if decoded.Observables[0].Value != "192.168.1.100" {
		t.Errorf("Observable[0].Value: got %q, want %q", decoded.Observables[0].Value, "192.168.1.100")
	}
	if len(decoded.Observables[0].Tags) != 1 || decoded.Observables[0].Tags[0] != "internal" {
		t.Errorf("Observable[0].Tags: got %v, want [internal]", decoded.Observables[0].Tags)
	}

	// Verify timeline entry content round-trips.
	if decoded.Timeline[0].ActionType != ActionEscalation {
		t.Errorf("Timeline[0].ActionType: got %q, want %q", decoded.Timeline[0].ActionType, ActionEscalation)
	}
}

func TestCaseJSONOmitsNilFields(t *testing.T) {
	c := Case{
		ID:       "case-002",
		Title:    "Test case",
		Status:   StatusNew,
		Severity: SeverityLow,
		Assignee: "unassigned",
		// Resolution and ClosedAt are nil.
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw failed: %v", err)
	}

	if _, ok := raw["resolution"]; ok {
		t.Error("nil resolution should be omitted from JSON")
	}
	if _, ok := raw["closed_at"]; ok {
		t.Error("nil closed_at should be omitted from JSON")
	}
}
