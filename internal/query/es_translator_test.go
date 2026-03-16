package query

import (
	"encoding/json"
	"testing"
)

// helper to parse and translate in one step.
func parseAndTranslate(t *testing.T, input string) *TranslateResult {
	t.Helper()
	q, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	tr, err := Translate(q)
	if err != nil {
		t.Fatalf("translate error: %v", err)
	}
	return tr
}

// helper to serialize the query to JSON for comparison.
func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal error: %v", err)
	}
	return string(b)
}

// --- Simple term queries ---

func TestTranslate_SimpleEquals(t *testing.T) {
	tr := parseAndTranslate(t, `process.name = "cmd.exe"`)

	term, ok := tr.Query["term"].(map[string]any)
	if !ok {
		t.Fatalf("expected term query, got %v", tr.Query)
	}
	if term["process.name"] != "cmd.exe" {
		t.Errorf("expected process.name = cmd.exe, got %v", term)
	}
}

func TestTranslate_NotEquals(t *testing.T) {
	tr := parseAndTranslate(t, `event.action != "logoff"`)

	boolQ := tr.Query["bool"].(map[string]any)
	mustNot := boolQ["must_not"].([]any)
	if len(mustNot) != 1 {
		t.Fatalf("expected 1 must_not clause, got %d", len(mustNot))
	}

	inner := mustNot[0].(map[string]any)
	term := inner["term"].(map[string]any)
	if term["event.action"] != "logoff" {
		t.Errorf("expected event.action = logoff, got %v", term)
	}
}

// --- Wildcard ---

func TestTranslate_Wildcard(t *testing.T) {
	tr := parseAndTranslate(t, `process.name = "cmd*"`)

	wc, ok := tr.Query["wildcard"].(map[string]any)
	if !ok {
		t.Fatalf("expected wildcard query, got %v", tr.Query)
	}
	inner := wc["process.name"].(map[string]any)
	if inner["value"] != "cmd*" {
		t.Errorf("expected cmd*, got %v", inner["value"])
	}
}

// --- Range queries ---

func TestTranslate_GreaterThan(t *testing.T) {
	tr := parseAndTranslate(t, `event.severity > 5`)

	rangeQ := tr.Query["range"].(map[string]any)
	field := rangeQ["event.severity"].(map[string]any)
	if field["gt"] != "5" {
		t.Errorf("expected gt 5, got %v", field)
	}
}

func TestTranslate_LessThan(t *testing.T) {
	tr := parseAndTranslate(t, `event.severity < 3`)

	rangeQ := tr.Query["range"].(map[string]any)
	field := rangeQ["event.severity"].(map[string]any)
	if field["lt"] != "3" {
		t.Errorf("expected lt 3, got %v", field)
	}
}

func TestTranslate_GTE(t *testing.T) {
	tr := parseAndTranslate(t, `event.severity >= 5`)

	rangeQ := tr.Query["range"].(map[string]any)
	field := rangeQ["event.severity"].(map[string]any)
	if field["gte"] != "5" {
		t.Errorf("expected gte 5, got %v", field)
	}
}

func TestTranslate_LTE(t *testing.T) {
	tr := parseAndTranslate(t, `event.severity <= 2`)

	rangeQ := tr.Query["range"].(map[string]any)
	field := rangeQ["event.severity"].(map[string]any)
	if field["lte"] != "2" {
		t.Errorf("expected lte 2, got %v", field)
	}
}

func TestTranslate_TimestampRange(t *testing.T) {
	tr := parseAndTranslate(t, `@timestamp > "2026-01-01T00:00:00Z"`)

	rangeQ := tr.Query["range"].(map[string]any)
	field := rangeQ["@timestamp"].(map[string]any)
	if field["gt"] != "2026-01-01T00:00:00Z" {
		t.Errorf("expected timestamp, got %v", field)
	}
}

// --- Boolean logic ---

func TestTranslate_AND(t *testing.T) {
	tr := parseAndTranslate(t, `process.name = "cmd.exe" AND user.name = "admin"`)

	boolQ := tr.Query["bool"].(map[string]any)
	must := boolQ["must"].([]any)
	if len(must) != 2 {
		t.Fatalf("expected 2 must clauses, got %d", len(must))
	}
}

func TestTranslate_OR(t *testing.T) {
	tr := parseAndTranslate(t, `event.action = "logon" OR event.action = "logoff"`)

	boolQ := tr.Query["bool"].(map[string]any)
	should := boolQ["should"].([]any)
	if len(should) != 2 {
		t.Fatalf("expected 2 should clauses, got %d", len(should))
	}
	msm := boolQ["minimum_should_match"]
	if msm != 1 {
		t.Errorf("expected minimum_should_match 1, got %v", msm)
	}
}

func TestTranslate_NOT(t *testing.T) {
	tr := parseAndTranslate(t, `NOT process.name = "explorer.exe"`)

	boolQ := tr.Query["bool"].(map[string]any)
	mustNot := boolQ["must_not"].([]any)
	if len(mustNot) != 1 {
		t.Fatalf("expected 1 must_not clause, got %d", len(mustNot))
	}
}

func TestTranslate_ComplexBoolean(t *testing.T) {
	tr := parseAndTranslate(t, `(process.name = "cmd.exe" AND user.name = "admin") OR event.action = "logon"`)

	boolQ := tr.Query["bool"].(map[string]any)
	should := boolQ["should"].([]any)
	if len(should) != 2 {
		t.Fatalf("expected 2 should clauses, got %d", len(should))
	}
}

func TestTranslate_TripleAND_Flattened(t *testing.T) {
	tr := parseAndTranslate(t, `a = "1" AND b = "2" AND c = "3"`)

	boolQ := tr.Query["bool"].(map[string]any)
	must := boolQ["must"].([]any)
	if len(must) != 3 {
		t.Fatalf("expected 3 flattened must clauses, got %d", len(must))
	}
}

func TestTranslate_TripleOR_Flattened(t *testing.T) {
	tr := parseAndTranslate(t, `a = "1" OR b = "2" OR c = "3"`)

	boolQ := tr.Query["bool"].(map[string]any)
	should := boolQ["should"].([]any)
	if len(should) != 3 {
		t.Fatalf("expected 3 flattened should clauses, got %d", len(should))
	}
}

// --- Exists ---

func TestTranslate_Exists(t *testing.T) {
	tr := parseAndTranslate(t, `process.parent.name exists`)

	exists := tr.Query["exists"].(map[string]any)
	if exists["field"] != "process.parent.name" {
		t.Errorf("expected process.parent.name, got %v", exists["field"])
	}
}

// --- IN (terms) ---

func TestTranslate_IN(t *testing.T) {
	tr := parseAndTranslate(t, `event.action IN ("logon", "logoff", "failed_logon")`)

	terms := tr.Query["terms"].(map[string]any)
	values := terms["event.action"].([]any)
	if len(values) != 3 {
		t.Fatalf("expected 3 terms, got %d", len(values))
	}
	if values[0] != "logon" || values[1] != "logoff" || values[2] != "failed_logon" {
		t.Errorf("unexpected terms: %v", values)
	}
}

// --- Match all ---

func TestTranslate_MatchAll(t *testing.T) {
	tr := parseAndTranslate(t, `*`)

	matchAll, ok := tr.Query["match_all"]
	if !ok {
		t.Fatalf("expected match_all, got %v", tr.Query)
	}
	// Should be an empty object.
	m := matchAll.(map[string]any)
	if len(m) != 0 {
		t.Errorf("expected empty match_all, got %v", m)
	}
}

func TestTranslate_EmptyQuery(t *testing.T) {
	tr := parseAndTranslate(t, ``)
	if _, ok := tr.Query["match_all"]; !ok {
		t.Fatalf("expected match_all for empty query, got %v", tr.Query)
	}
}

// --- Pipe stages ---

func TestTranslate_SortDesc(t *testing.T) {
	tr := parseAndTranslate(t, `process.name = "cmd.exe" | sort @timestamp desc`)

	if len(tr.Sort) != 1 {
		t.Fatalf("expected 1 sort clause, got %d", len(tr.Sort))
	}
	sortEntry := tr.Sort[0]["@timestamp"].(map[string]any)
	if sortEntry["order"] != "desc" {
		t.Errorf("expected desc, got %v", sortEntry["order"])
	}
}

func TestTranslate_SortAsc(t *testing.T) {
	tr := parseAndTranslate(t, `* | sort event.severity asc`)

	sortEntry := tr.Sort[0]["event.severity"].(map[string]any)
	if sortEntry["order"] != "asc" {
		t.Errorf("expected asc, got %v", sortEntry["order"])
	}
}

func TestTranslate_Limit(t *testing.T) {
	tr := parseAndTranslate(t, `user.name = "admin" | limit 100`)

	if tr.Size != 100 {
		t.Errorf("expected size 100, got %d", tr.Size)
	}
}

func TestTranslate_Head(t *testing.T) {
	tr := parseAndTranslate(t, `user.name = "admin" | head 50`)

	if tr.Size != 50 {
		t.Errorf("expected size 50, got %d", tr.Size)
	}
}

func TestTranslate_Fields(t *testing.T) {
	tr := parseAndTranslate(t, `user.name = "admin" | fields user.name, process.name, @timestamp`)

	if len(tr.Source) != 3 {
		t.Fatalf("expected 3 source fields, got %d", len(tr.Source))
	}
	if tr.Source[0] != "user.name" || tr.Source[1] != "process.name" || tr.Source[2] != "@timestamp" {
		t.Errorf("unexpected source fields: %v", tr.Source)
	}
}

func TestTranslate_MultiplePipes(t *testing.T) {
	tr := parseAndTranslate(t, `process.name = "cmd.exe" | sort @timestamp desc | limit 100`)

	if len(tr.Sort) != 1 {
		t.Errorf("expected 1 sort, got %d", len(tr.Sort))
	}
	if tr.Size != 100 {
		t.Errorf("expected size 100, got %d", tr.Size)
	}
}

// --- Aggregations ---

func TestTranslate_CountAgg(t *testing.T) {
	tr := parseAndTranslate(t, `count() by user.name where event.action = "failed_logon"`)

	if tr.Aggs == nil {
		t.Fatal("expected aggregations")
	}

	// Should have group_by_user.name terms aggregation.
	groupBy, ok := tr.Aggs["group_by_user.name"].(map[string]any)
	if !ok {
		t.Fatalf("expected group_by_user.name agg, got %v", tr.Aggs)
	}
	terms := groupBy["terms"].(map[string]any)
	if terms["field"] != "user.name" {
		t.Errorf("expected terms field user.name, got %v", terms["field"])
	}

	// Query should be the where clause.
	term := tr.Query["term"].(map[string]any)
	if term["event.action"] != "failed_logon" {
		t.Errorf("expected where filter, got %v", tr.Query)
	}

	// Size should be 0 for aggregations (no hits needed).
	if tr.Size != 0 {
		t.Errorf("expected size 0 for agg, got %d", tr.Size)
	}
}

func TestTranslate_SumAgg(t *testing.T) {
	tr := parseAndTranslate(t, `sum(event.risk_score) by host.name`)

	groupBy := tr.Aggs["group_by_host.name"].(map[string]any)
	subAggs := groupBy["aggs"].(map[string]any)
	sumAgg := subAggs["sum_event.risk_score"].(map[string]any)
	sumInner := sumAgg["sum"].(map[string]any)
	if sumInner["field"] != "event.risk_score" {
		t.Errorf("expected sum field event.risk_score, got %v", sumInner)
	}
}

func TestTranslate_CountMultiGroupBy(t *testing.T) {
	tr := parseAndTranslate(t, `count() by user.name, host.name`)

	// Should be nested: group_by_user.name → group_by_host.name.
	outer := tr.Aggs["group_by_user.name"].(map[string]any)
	innerAggs := outer["aggs"].(map[string]any)
	inner := innerAggs["group_by_host.name"].(map[string]any)
	terms := inner["terms"].(map[string]any)
	if terms["field"] != "host.name" {
		t.Errorf("expected inner field host.name, got %v", terms)
	}
}

// --- BuildSearchBody ---

func TestBuildSearchBody_Full(t *testing.T) {
	tr := parseAndTranslate(t, `process.name = "cmd.exe" | sort @timestamp desc | limit 50 | fields process.name, user.name`)

	body := BuildSearchBody(tr)

	if body["query"] == nil {
		t.Error("expected query in body")
	}
	if body["size"] != 50 {
		t.Errorf("expected size 50, got %v", body["size"])
	}
	if body["sort"] == nil {
		t.Error("expected sort in body")
	}
	src := body["_source"].([]string)
	if len(src) != 2 {
		t.Errorf("expected 2 source fields, got %d", len(src))
	}
}

func TestBuildSearchBody_MatchAll(t *testing.T) {
	tr := parseAndTranslate(t, ``)
	body := BuildSearchBody(tr)

	// Should have match_all query, no sort/size/source.
	if _, ok := body["query"].(map[string]any)["match_all"]; !ok {
		t.Error("expected match_all in body")
	}
	if _, ok := body["size"]; ok {
		t.Error("expected no size for match_all")
	}
	if _, ok := body["sort"]; ok {
		t.Error("expected no sort for match_all")
	}
}

func TestBuildSearchBody_WithAgg(t *testing.T) {
	tr := parseAndTranslate(t, `count() by user.name where event.action = "logon"`)
	body := BuildSearchBody(tr)

	if body["aggs"] == nil {
		t.Error("expected aggs in body")
	}
	// Size should not be set (0 means omitted by BuildSearchBody).
	if _, ok := body["size"]; ok {
		t.Error("expected no size key for agg query")
	}
}

// --- JSON roundtrip ---

func TestTranslate_JSONRoundtrip(t *testing.T) {
	input := `process.name = "cmd.exe" AND user.name != "SYSTEM" | sort @timestamp desc | limit 100`
	tr := parseAndTranslate(t, input)
	body := BuildSearchBody(tr)

	// Should produce valid JSON.
	jsonBytes, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal to JSON: %v", err)
	}

	// Verify it roundtrips.
	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if parsed["size"] != float64(100) {
		t.Errorf("expected size 100, got %v", parsed["size"])
	}
}

// --- Requirements example: equivalent to Kibana query ---

func TestTranslate_KibanaEquivalent(t *testing.T) {
	// This is the kind of query an analyst would type:
	// "Show me all cmd.exe executions by non-SYSTEM users in the last hour, sorted newest first"
	input := `process.name = "cmd.exe" AND user.name != "SYSTEM" AND @timestamp >= "2026-01-01T00:00:00Z" | sort @timestamp desc | limit 50 | fields @timestamp, user.name, process.name, process.command_line`

	tr := parseAndTranslate(t, input)
	body := BuildSearchBody(tr)

	// Verify structure.
	if body["size"] != 50 {
		t.Errorf("expected size 50")
	}

	sort := body["sort"].([]map[string]any)
	if len(sort) != 1 {
		t.Errorf("expected 1 sort clause")
	}

	src := body["_source"].([]string)
	if len(src) != 4 {
		t.Errorf("expected 4 source fields, got %d", len(src))
	}

	// The query should have 3 must clauses.
	boolQ := body["query"].(map[string]any)["bool"].(map[string]any)
	must := boolQ["must"].([]any)
	if len(must) != 3 {
		t.Fatalf("expected 3 must clauses, got %d", len(must))
	}
}
