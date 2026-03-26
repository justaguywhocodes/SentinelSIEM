package normalize

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// sourceTypeEnvelope is used for lightweight extraction of source_type from raw JSON.
// Also checks the "schema" field as a fallback for sources that use schema-based routing
// (e.g., AkesoEDR sends "schema": "akesoedr/v1" instead of "source_type").
type sourceTypeEnvelope struct {
	SourceType string `json:"source_type"`
	Schema     string `json:"schema"`
}

// schemaToSourceType maps known schema identifiers to parser source types.
var schemaToSourceType = map[string]string{
	"akesoedr/v1": "akeso_edr",
}

// Engine routes raw events to the correct parser based on source_type.
type Engine struct {
	registry *Registry
}

// NewEngine creates a normalization engine backed by the given parser registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// Normalize takes a raw event, extracts its source_type, routes it to the
// appropriate parser, and returns the normalized ECS event.
// Unknown or missing source_type → raw preserved in a minimal ECSEvent.
func (e *Engine) Normalize(raw json.RawMessage) (*common.ECSEvent, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("normalize: invalid JSON")
	}

	// Extract source_type with lightweight partial unmarshal.
	var envelope sourceTypeEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("normalize: extracting source_type: %w", err)
	}

	// Fall back to schema field if source_type is missing.
	if envelope.SourceType == "" && envelope.Schema != "" {
		if mapped, ok := schemaToSourceType[envelope.Schema]; ok {
			envelope.SourceType = mapped
		}
	}

	// Look up parser.
	if envelope.SourceType != "" {
		if parser := e.registry.Lookup(envelope.SourceType); parser != nil {
			event, err := parser.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("normalize: parser %q: %w", envelope.SourceType, err)
			}
			// Always preserve raw and source type for index routing.
			event.Raw = raw
			event.SourceType = envelope.SourceType
			return event, nil
		}
	}

	// Unknown or missing source_type — preserve raw in a minimal event.
	sourceType := envelope.SourceType
	if sourceType == "" {
		sourceType = "unknown"
	}
	return &common.ECSEvent{
		Timestamp:  time.Now().UTC(),
		SourceType: sourceType,
		Event: &common.EventFields{
			Kind: "event",
		},
		Raw: raw,
	}, nil
}

// NormalizeBatch normalizes a slice of raw events, returning results and any errors.
// Processing continues past individual event errors.
func (e *Engine) NormalizeBatch(rawEvents []json.RawMessage) ([]*common.ECSEvent, []error) {
	events := make([]*common.ECSEvent, 0, len(rawEvents))
	var errs []error

	for _, raw := range rawEvents {
		event, err := e.Normalize(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		events = append(events, event)
	}

	return events, errs
}
