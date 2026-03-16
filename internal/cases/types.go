package cases

import (
	"encoding/json"
	"time"
)

// Case status workflow: new → in_progress → resolved → closed.
const (
	StatusNew        = "new"
	StatusInProgress = "in_progress"
	StatusResolved   = "resolved"
	StatusClosed     = "closed"
)

// Case severity levels.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Resolution types for case closure.
const (
	ResolutionTruePositive  = "true_positive"
	ResolutionFalsePositive = "false_positive"
	ResolutionBenign        = "benign"
	ResolutionDuplicate     = "duplicate"
)

// Observable types.
const (
	ObservableIP          = "ip"
	ObservableHash        = "hash"
	ObservableDomain      = "domain"
	ObservableUser        = "user"
	ObservableProcess     = "process"
	ObservableJA3         = "ja3"
	ObservableJA4         = "ja4"
	ObservableCommunityID = "community_id"
	ObservableSNI         = "sni"
)

// Timeline action types.
const (
	ActionComment         = "comment"
	ActionStatusChange    = "status_change"
	ActionObservableAdded = "observable_added"
	ActionAlertMerged     = "alert_merged"
	ActionEscalation      = "escalation"
	ActionResolution      = "resolution"
	ActionAssigneeChanged = "assignee_changed"
	ActionSeverityChanged = "severity_changed"
)

// Case represents an incident case document stored in Elasticsearch.
type Case struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Status      string          `json:"status"`
	Severity    string          `json:"severity"`
	Assignee    string          `json:"assignee"`
	AlertIDs    []string        `json:"alert_ids"`
	Observables []Observable    `json:"observables"`
	Timeline    []TimelineEntry `json:"timeline"`
	Tags        []string        `json:"tags"`
	Resolution  *Resolution     `json:"resolution,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ClosedAt    *time.Time      `json:"closed_at,omitempty"`

	// SeqNo and PrimaryTerm are used for optimistic concurrency control.
	SeqNo       *int `json:"_seq_no,omitempty"`
	PrimaryTerm *int `json:"_primary_term,omitempty"`
}

// Observable represents an extracted entity from alert events.
type Observable struct {
	Type    string   `json:"type"`
	Value   string   `json:"value"`
	Source  string   `json:"source"`
	Tags    []string `json:"tags,omitempty"`
}

// TimelineEntry represents a single entry in the case activity log.
type TimelineEntry struct {
	Timestamp  time.Time       `json:"timestamp"`
	Author     string          `json:"author"`
	ActionType string          `json:"action_type"`
	Content    json.RawMessage `json:"content"`
}

// Resolution holds the required resolution details when closing a case.
type Resolution struct {
	Type  string `json:"type"`
	Notes string `json:"notes,omitempty"`
}

// validStatuses is the set of all valid case statuses.
var validStatuses = map[string]bool{
	StatusNew:        true,
	StatusInProgress: true,
	StatusResolved:   true,
	StatusClosed:     true,
}

// validSeverities is the set of all valid severity levels.
var validSeverities = map[string]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
}

// validResolutions is the set of all valid resolution types.
var validResolutions = map[string]bool{
	ResolutionTruePositive:  true,
	ResolutionFalsePositive: true,
	ResolutionBenign:        true,
	ResolutionDuplicate:     true,
}

// validObservableTypes is the set of all valid observable types.
var validObservableTypes = map[string]bool{
	ObservableIP:          true,
	ObservableHash:        true,
	ObservableDomain:      true,
	ObservableUser:        true,
	ObservableProcess:     true,
	ObservableJA3:         true,
	ObservableJA4:         true,
	ObservableCommunityID: true,
	ObservableSNI:         true,
}

// statusOrder defines the allowed state transitions.
// A status can only transition to a status with a higher order number.
var statusOrder = map[string]int{
	StatusNew:        0,
	StatusInProgress: 1,
	StatusResolved:   2,
	StatusClosed:     3,
}

// IsValidStatus returns true if s is a valid case status.
func IsValidStatus(s string) bool {
	return validStatuses[s]
}

// IsValidSeverity returns true if s is a valid case severity.
func IsValidSeverity(s string) bool {
	return validSeverities[s]
}

// IsValidResolution returns true if r is a valid resolution type.
func IsValidResolution(r string) bool {
	return validResolutions[r]
}

// IsValidObservableType returns true if t is a valid observable type.
func IsValidObservableType(t string) bool {
	return validObservableTypes[t]
}

// CanTransition returns true if the status transition from → to is allowed.
// Allowed transitions follow the workflow: new → in_progress → resolved → closed.
// Reopening is also allowed: resolved → in_progress, closed → in_progress.
func CanTransition(from, to string) bool {
	if from == to {
		return false
	}
	if !IsValidStatus(from) || !IsValidStatus(to) {
		return false
	}

	// Forward transitions: must go to a higher state.
	fromOrder := statusOrder[from]
	toOrder := statusOrder[to]
	if toOrder > fromOrder {
		return true
	}

	// Reopen: resolved or closed can go back to in_progress.
	if (from == StatusResolved || from == StatusClosed) && to == StatusInProgress {
		return true
	}

	return false
}

// SeverityRank returns a numeric rank for severity (higher = more severe).
// Used for selecting the highest severity when merging alerts.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// HighestSeverity returns the highest severity from a list.
func HighestSeverity(severities []string) string {
	best := ""
	bestRank := -1
	for _, s := range severities {
		if r := SeverityRank(s); r > bestRank {
			bestRank = r
			best = s
		}
	}
	if best == "" {
		return SeverityLow
	}
	return best
}
