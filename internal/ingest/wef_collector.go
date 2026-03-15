package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WEFCollector handles Windows Event Forwarding HTTP requests.
// It accepts raw XML events, JSON-wrapped XML, or Winlogbeat JSON and
// routes them through the standard ingest pipeline.
type WEFCollector struct {
	handler EventHandler
}

// NewWEFCollector creates a WEF collector that delegates to the given handler.
func NewWEFCollector(handler EventHandler) *WEFCollector {
	return &WEFCollector{handler: handler}
}

// HandleWEF processes a WEF HTTP request. It detects the format (XML vs JSON),
// splits batch XML into individual events, wraps each as JSON, and passes them
// to the pipeline.
func (c *WEFCollector) HandleWEF(w http.ResponseWriter, r *http.Request) {
	// Read body (10MB max, matching existing ingest endpoint).
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, `{"error":"empty body"}`, http.StatusBadRequest)
		return
	}

	// Detect format.
	format := detectFormat(r.Header.Get("Content-Type"), body)

	var events []json.RawMessage

	switch format {
	case "xml":
		events, err = splitAndWrapXMLEvents(body)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
	case "json":
		// Parse as NDJSON or JSON array (same as main ingest endpoint).
		events, err = parseEvents(body)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		// Auto-detect and tag events that don't have source_type.
		events = tagWEFEvents(events)
	default:
		http.Error(w, `{"error":"unsupported format: expected XML or JSON"}`, http.StatusBadRequest)
		return
	}

	if len(events) == 0 {
		http.Error(w, `{"error":"no events found in body"}`, http.StatusBadRequest)
		return
	}

	// Deliver to handler.
	if c.handler != nil {
		c.handler(events)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"accepted": len(events),
	})
}

// detectFormat determines the payload format from Content-Type header and body sniffing.
func detectFormat(contentType string, body []byte) string {
	ct := strings.ToLower(contentType)

	// Check Content-Type header first.
	if strings.Contains(ct, "xml") {
		return "xml"
	}
	if strings.Contains(ct, "json") {
		return "json"
	}

	// Sniff first non-whitespace byte.
	trimmed := trimLeftSpace(body)
	// Strip BOM if present.
	if len(trimmed) >= 3 && trimmed[0] == 0xEF && trimmed[1] == 0xBB && trimmed[2] == 0xBF {
		trimmed = trimmed[3:]
		trimmed = trimLeftSpace(trimmed)
	}

	if len(trimmed) == 0 {
		return "unknown"
	}

	switch trimmed[0] {
	case '<':
		return "xml"
	case '{', '[':
		return "json"
	default:
		return "unknown"
	}
}

// splitAndWrapXMLEvents extracts individual <Event>...</Event> blocks from XML input
// and wraps each as a JSON envelope for the normalization pipeline.
//
// Handles:
//   - Single <Event>...</Event>
//   - Batch <Events><Event>...</Event><Event>...</Event></Events>
//   - Multiple <Event> blocks without wrapper
func splitAndWrapXMLEvents(body []byte) ([]json.RawMessage, error) {
	// Strip BOM if present.
	if len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF {
		body = body[3:]
	}

	// Find all <Event ... > ... </Event> blocks.
	blocks := extractEventBlocks(body)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no <Event> elements found in XML")
	}

	events := make([]json.RawMessage, 0, len(blocks))
	for _, block := range blocks {
		// Wrap each XML block in a JSON envelope.
		envelope := map[string]string{
			"source_type": "winevt_xml",
			"xml":         string(block),
		}
		data, err := json.Marshal(envelope)
		if err != nil {
			continue // skip malformed blocks
		}
		events = append(events, data)
	}

	return events, nil
}

// extractEventBlocks finds all <Event>...</Event> blocks in the input.
// Uses simple string scanning — no full XML parse needed.
func extractEventBlocks(data []byte) [][]byte {
	var blocks [][]byte
	s := string(data)
	pos := 0

	for pos < len(s) {
		// Find start of <Event (case-insensitive search not needed — Windows uses <Event).
		startIdx := indexEventStart(s, pos)
		if startIdx < 0 {
			break
		}

		// Find matching </Event>.
		endTag := "</Event>"
		endIdx := strings.Index(s[startIdx:], endTag)
		if endIdx < 0 {
			// Try case variation.
			endTag = "</event>"
			endIdx = strings.Index(strings.ToLower(s[startIdx:]), endTag)
			if endIdx < 0 {
				break // No closing tag — truncated XML
			}
		}

		block := s[startIdx : startIdx+endIdx+len(endTag)]
		blocks = append(blocks, []byte(block))
		pos = startIdx + endIdx + len(endTag)
	}

	return blocks
}

// indexEventStart finds the next <Event or <Event> tag start.
func indexEventStart(s string, from int) int {
	sub := s[from:]

	// Look for <Event (with space or > after).
	idx := 0
	for idx < len(sub) {
		i := strings.Index(sub[idx:], "<Event")
		if i < 0 {
			return -1
		}
		absIdx := idx + i
		afterTag := absIdx + len("<Event")
		if afterTag >= len(sub) {
			return from + absIdx
		}
		ch := sub[afterTag]
		if ch == '>' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			return from + absIdx
		}
		// Skip past (e.g., <EventData or <EventRecordID).
		idx = absIdx + 1
	}

	return -1
}

// tagWEFEvents ensures JSON events coming through the WEF endpoint have
// appropriate source_type set for routing.
func tagWEFEvents(events []json.RawMessage) []json.RawMessage {
	tagged := make([]json.RawMessage, 0, len(events))

	for _, raw := range events {
		var probe struct {
			SourceType string          `json:"source_type"`
			Winlog     json.RawMessage `json:"winlog"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			tagged = append(tagged, raw)
			continue
		}

		// If already tagged, pass through.
		if probe.SourceType != "" {
			tagged = append(tagged, raw)
			continue
		}

		// Auto-detect: has winlog → winevt_json.
		if probe.Winlog != nil {
			tagged = append(tagged, injectSourceType(raw, "winevt_json"))
		} else {
			tagged = append(tagged, raw)
		}
	}

	return tagged
}

// injectSourceType adds source_type to a JSON object.
func injectSourceType(raw json.RawMessage, sourceType string) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	stBytes, _ := json.Marshal(sourceType)
	obj["source_type"] = stBytes
	result, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return result
}

// splitXMLEventsReader is a helper for testing — reads all XML events from a reader.
func splitXMLEventsReader(r io.Reader) ([][]byte, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	blocks := extractEventBlocks(buf.Bytes())
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no <Event> elements found")
	}
	return blocks, nil
}
