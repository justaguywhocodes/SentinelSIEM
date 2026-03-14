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
	reg.Register(&testParser{sourceType: "sentineledr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel")

	// Send 5 events.
	events := make([]json.RawMessage, 5)
	for i := range events {
		events[i] = makeTestEvent("sentineledr")
	}

	pipeline.Handle(events)

	if indexer.totalEvents() != 5 {
		t.Errorf("total indexed events = %d, want 5", indexer.totalEvents())
	}
}

func TestPipelineIndexNaming(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentineledr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel")

	pipeline.Handle([]json.RawMessage{makeTestEvent("sentineledr")})

	names := indexer.indexNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 index, got %d", len(names))
	}

	// Index should match pattern: sentinel-events-sentineledr-YYYY.MM.dd
	expected := "sentinel-events-sentineledr-"
	if len(names[0]) < len(expected) || names[0][:len(expected)] != expected {
		t.Errorf("index name = %q, want prefix %q", names[0], expected)
	}
}

func TestPipelineUnknownSourceType(t *testing.T) {
	reg := normalize.NewRegistry()
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel")

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
	pipeline := NewPipeline(engine, indexer, "sentinel")

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
	reg.Register(&testParser{sourceType: "sentineledr"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel")

	events := []json.RawMessage{
		makeTestEvent("sentineledr"),
		json.RawMessage(`{broken json`),
		makeTestEvent("sentineledr"),
		json.RawMessage(`{also broken`),
		makeTestEvent("sentineledr"),
	}

	pipeline.Handle(events)

	// 3 valid events should be indexed, 2 malformed skipped.
	if indexer.totalEvents() != 3 {
		t.Errorf("total indexed events = %d, want 3", indexer.totalEvents())
	}
}

func TestPipelineMultipleSourceTypes(t *testing.T) {
	reg := normalize.NewRegistry()
	reg.Register(&testParser{sourceType: "sentineledr"})
	reg.Register(&testParser{sourceType: "sentinel_av"})
	engine := normalize.NewEngine(reg)
	indexer := &mockIndexer{}
	pipeline := NewPipeline(engine, indexer, "sentinel")

	events := []json.RawMessage{
		makeTestEvent("sentineledr"),
		makeTestEvent("sentineledr"),
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
		if contains(call.Index, "sentineledr") && len(call.Events) != 2 {
			t.Errorf("sentineledr group: got %d events, want 2", len(call.Events))
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
	pipeline := NewPipeline(engine, indexer, "sentinel")

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
	pipeline := NewPipeline(engine, indexer, "")

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
	pipeline := NewPipeline(engine, indexer, "myorg")

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
