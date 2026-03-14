package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
	"github.com/SentinelSIEM/sentinel-siem/internal/normalize"
	"github.com/SentinelSIEM/sentinel-siem/internal/store"
)

// Pipeline wires together the ingestion components:
// HTTPListener → normalize.Engine → store.Indexer (Elasticsearch).
type Pipeline struct {
	engine  *normalize.Engine
	indexer store.Indexer
	prefix  string
}

// NewPipeline creates an ingestion pipeline.
func NewPipeline(engine *normalize.Engine, indexer store.Indexer, prefix string) *Pipeline {
	if prefix == "" {
		prefix = "sentinel"
	}
	return &Pipeline{
		engine:  engine,
		indexer: indexer,
		prefix:  prefix,
	}
}

// Handle is the EventHandler callback for HTTPListener. It normalizes a batch
// of raw events and indexes them into Elasticsearch, grouped by source type.
func (p *Pipeline) Handle(rawEvents []json.RawMessage) {
	if len(rawEvents) == 0 {
		return
	}

	// Normalize.
	events, errs := p.engine.NormalizeBatch(rawEvents)
	for _, err := range errs {
		log.Printf("[pipeline] normalization error: %v", err)
	}

	if len(events) == 0 {
		return
	}

	// Group events by target index.
	groups := p.groupByIndex(events)

	// Bulk index each group.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for index, batch := range groups {
		if err := p.indexer.BulkIndex(ctx, index, batch); err != nil {
			log.Printf("[pipeline] indexing error for %s: %v", index, err)
		}
	}
}

// groupByIndex partitions events into per-index batches.
// Index pattern: {prefix}-events-{source_type}-{YYYY.MM.dd}
func (p *Pipeline) groupByIndex(events []*common.ECSEvent) map[string][]common.ECSEvent {
	groups := make(map[string][]common.ECSEvent)

	for _, event := range events {
		index := p.indexName(event)
		groups[index] = append(groups[index], *event)
	}

	return groups
}

// indexName computes the target ES index for an event.
func (p *Pipeline) indexName(event *common.ECSEvent) string {
	sourceType := event.SourceType
	if sourceType == "" {
		sourceType = "unknown"
	}

	date := event.Timestamp.UTC().Format("2006.01.02")

	return fmt.Sprintf("%s-events-%s-%s", p.prefix, sourceType, date)
}
