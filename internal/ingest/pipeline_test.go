package ingest

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
)

// mockIndexer captures BulkIndex calls for verification.
type mockIndexer struct {
	mu      sync.Mutex
	calls   []bulkIndexCall
	failErr error // if set, BulkIndex returns this error
}

type bulkIndexCall struct {
	Index  string
	Events []common.ECSEvent
}

func (m *mockIndexer) BulkIndex(_ context.Context, index string, events []common.ECSEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, bulkIndexCall{Index: index, Events: events})
	return m.failErr
}

func (m *mockIndexer) totalEvents() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, c := range m.calls {
		total += len(c.Events)
	}
	return total
}

func (m *mockIndexer) indexNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for _, c := range m.calls {
		names = append(names, c.Index)
	}
	return names
}

// testParser returns a fixed ECSEvent for testing.
type testParser struct {
	sourceType string
}

func (p *testParser) SourceType() string { return p.sourceType }

func (p *testParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
		},
		Process: &common.ProcessFields{
			PID:  1234,
			Name: "test.exe",
		},
	}, nil
}

// makeTestEvent creates a minimal SIEM-envelope event for pipeline testing.
func makeTestEvent(sourceType string) json.RawMessage {
	event := map[string]any{
		"source_type": sourceType,
		"timestamp":   "2026-03-14T12:00:00Z",
		"event": map[string]any{
			"eventId":   "test-id",
			"timestamp": "2026-03-14T12:00:00Z",
			"source":    "DriverProcess",
			"severity":  "Low",
			"process": map[string]any{
				"pid":       1234,
				"imagePath": `C:\test.exe`,
			},
			"payload": map[string]any{
				"isCreate": true,
			},
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func TestPipelineNormalizeAndIndex(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentinel_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	// Send 5 events.
	events := make([]json.RawMessage, 5)
	for i := range events {
		events[i] = makeTestEvent("sentinel_edr")
	}

	pipeline.Handle(events)

	if indexer.totalEvents() != 5 {
		t.Errorf("total indexed events = %d, want 5", indexer.totalEvents())
	}
}

func TestPipelineIndexNaming(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentinel_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	pipeline.Handle([]json.RawMessage{makeTestEvent("sentinel_edr")})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	// Index should match pattern: sentinel-events-sentinel_edr-YYYY.MM.dd
	expected := "sentinel-events-sentinel_edr-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineUnknownSourceType(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	raw := json.RawMessage(`{"source_type":"futuretype","data":"test"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "sentinel-events-futuretype-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineMissingSourceType(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	raw := json.RawMessage(`{"data":"no source type"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "sentinel-events-unknown-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineMixedValidInvalid(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentinel_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	events := []json.RawMessage{
		makeTestEvent("sentinel_edr"),
		json.RawMessage(`{broken json`),
		makeTestEvent("sentinel_edr"),
		json.RawMessage(`{also broken`),
		makeTestEvent("sentinel_edr"),
	}

	pipeline.Handle(events)

	// 3 valid events should be indexed, 2 malformed skipped.
	if indexer.totalEvents() != 3 {
		t.Errorf("total indexed events = %d, want 3", indexer.totalEvents())
	}
}

func TestPipelineMultipleSourceTypes(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentinel_edr"})
	reg.Register(&testParser{sourceType: "sentinel_av"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	events := []json.RawMessage{
		makeTestEvent("sentinel_edr"),
		makeTestEvent("sentinel_edr"),
		makeTestEvent("sentinel_av"),
	}

	pipeline.Handle(events)

	// Should create 2 index groups.
	names := indexer.indexNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 index groups, got %d: %v", len(names), names)
	}

	// Verify event counts per group.
	indexer.mu.Lock()
	defer indexer.mu.Unlock()
	for _, call := range indexer.calls {
		if contains(call.Index, "sentinel_edr") && len(call.Events) != 2 {
			t.Errorf("sentinel_edr group: got %d events, want 2", len(call.Events))
		}
		if contains(call.Index, "sentinel_av") && len(call.Events) != 1 {
			t.Errorf("sentinel_av group: got %d events, want 1", len(call.Events))
		}
	}
}

func TestPipelineEmptyBatch(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	// Should not panic or call indexer.
	pipeline.Handle(nil)
	pipeline.Handle([]json.RawMessage{})

	if indexer.totalEvents() != 0 {
		t.Errorf("expected 0 indexed events, got %d", indexer.totalEvents())
	}
}

func TestPipelineDefaultPrefix(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "", nil)

	raw := json.RawMessage(`{"source_type":"test","data":"x"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "sentinel-events-test-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineCustomPrefix(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "myorg", nil)

	raw := json.RawMessage(`{"source_type":"test","data":"x"}`)
	pipeline.Handle([]json.RawMessage{raw})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	expected := "myorg-events-test-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

// --- Host score upsert tests ---

// mockHostScoreIndexer captures UpsertHostScore calls.
type mockHostScoreIndexer struct {
	mu     sync.Mutex
	calls  []*common.ECSEvent
	failErr error
}

func (m *mockHostScoreIndexer) UpsertHostScore(_ context.Context, event *common.ECSEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, event)
	return m.failErr
}

func (m *mockHostScoreIndexer) upsertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// hostScoreParser returns an NDR host_score event.
type hostScoreParser struct{}

func (p *hostScoreParser) SourceType() string { return "sentinel_ndr" }

func (p *hostScoreParser) Parse(raw json.RawMessage) (*common.ECSEvent, error) {
	return &common.ECSEvent{
		Timestamp: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		Event: &common.EventFields{
			Kind:     "event",
			Category: []string{"host"},
			Type:     []string{"info"},
			Action:   "host_score_update",
		},
		Host: &common.HostFields{
			Name: "HOST-A",
			IP:   []string{"10.0.0.1"},
		},
		NDR: &common.NDRFields{
			HostScore: &common.NDRHostScore{
				Threat:    85,
				Certainty: 90,
				Quadrant:  "high_high",
			},
		},
	}, nil
}

func TestPipelineHostScoreUpsert(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&hostScoreParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	hsIndexer := &mockHostScoreIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", hsIndexer)

	events := []json.RawMessage{
		makeTestNDRHostScoreEvent(),
	}
	pipeline.Handle(events)

	// Event should be indexed in normal time-series index.
	if indexer.totalEvents() != 1 {
		t.Errorf("indexed events = %d, want 1", indexer.totalEvents())
	}

	// Event should also be upserted to host score index.
	if hsIndexer.upsertCount() != 1 {
		t.Errorf("host score upserts = %d, want 1", hsIndexer.upsertCount())
	}
}

func TestPipelineHostScoreNotUpsertedForNonHostScore(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentinel_edr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	hsIndexer := &mockHostScoreIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", hsIndexer)

	events := []json.RawMessage{makeTestEvent("sentinel_edr")}
	pipeline.Handle(events)

	// Regular events should NOT trigger host score upsert.
	if hsIndexer.upsertCount() != 0 {
		t.Errorf("host score upserts = %d, want 0", hsIndexer.upsertCount())
	}
}

func TestPipelineHostScoreNilIndexer(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&hostScoreParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	// nil host score indexer — should not panic.
	pipeline := NewPipeline(engine, indexer, "sentinel", nil)

	events := []json.RawMessage{makeTestNDRHostScoreEvent()}
	pipeline.Handle(events) // Should not panic.

	if indexer.totalEvents() != 1 {
		t.Errorf("indexed events = %d, want 1", indexer.totalEvents())
	}
}

func TestPipelineMultipleHostScoreEvents(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&hostScoreParser{})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	hsIndexer := &mockHostScoreIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel", hsIndexer)

	events := []json.RawMessage{
		makeTestNDRHostScoreEvent(),
		makeTestNDRHostScoreEvent(),
		makeTestNDRHostScoreEvent(),
	}
	pipeline.Handle(events)

	if hsIndexer.upsertCount() != 3 {
		t.Errorf("host score upserts = %d, want 3", hsIndexer.upsertCount())
	}
}

func TestIsHostScoreEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    *common.ECSEvent
		expected bool
	}{
		{"nil event", nil, false},
		{"empty event", &common.ECSEvent{}, false},
		{"no event fields", &common.ECSEvent{NDR: &common.NDRFields{HostScore: &common.NDRHostScore{}}}, false},
		{"wrong action", &common.ECSEvent{
			Event: &common.EventFields{Action: "session"},
			NDR:   &common.NDRFields{HostScore: &common.NDRHostScore{}},
		}, false},
		{"correct host_score", &common.ECSEvent{
			Event: &common.EventFields{Action: "host_score_update"},
			NDR:   &common.NDRFields{HostScore: &common.NDRHostScore{Threat: 50}},
		}, true},
		{"missing NDR", &common.ECSEvent{
			Event: &common.EventFields{Action: "host_score_update"},
		}, false},
		{"missing HostScore", &common.ECSEvent{
			Event: &common.EventFields{Action: "host_score_update"},
			NDR:   &common.NDRFields{},
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHostScoreEvent(tc.event); got != tc.expected {
				t.Errorf("isHostScoreEvent() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func makeTestNDRHostScoreEvent() json.RawMessage {
	event := map[string]any{
		"source_type": "sentinel_ndr",
		"timestamp":   "2026-03-15T10:00:00Z",
		"event_type":  "ndr:host_score",
	}
	data, _ := json.Marshal(event)
	return data
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
