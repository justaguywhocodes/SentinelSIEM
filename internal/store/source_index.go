package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// sourceIndexName returns the dedicated source config index name.
func (s *Store) sourceIndexName() string {
	return s.prefix + "-sources"
}

// SourceIndexName returns the source index name for external use.
func (s *Store) SourceIndexName() string {
	return s.sourceIndexName()
}

// EnsureSourceIndex creates the dedicated source config index with appropriate
// mappings if it doesn't already exist.
func (s *Store) EnsureSourceIndex(ctx context.Context) error {
	indexName := s.sourceIndexName()

	res, err := s.client.Indices.Exists([]string{indexName},
		s.client.Indices.Exists.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("checking source index: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		return nil
	}

	mappings := sourceIndexMappings()
	body, err := json.Marshal(mappings)
	if err != nil {
		return fmt.Errorf("marshaling source index mappings: %w", err)
	}

	res, err = s.client.Indices.Create(
		indexName,
		s.client.Indices.Create.WithContext(ctx),
		s.client.Indices.Create.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return fmt.Errorf("creating source index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("source index creation: %s", res.String())
	}

	return nil
}

// sourceIndexMappings returns the index creation body with field mappings
// for the dedicated source config index.
func sourceIndexMappings() map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"id":             mapping("keyword"),
				"name":           mapping("keyword"),
				"type":           mapping("keyword"),
				"protocol":       mapping("keyword"),
				"port":           mapping("integer"),
				"parser":         mapping("keyword"),
				"expected_hosts": mapping("keyword"),
				"api_key_id":     mapping("keyword"),
				"status":         mapping("keyword"),
				"description":    mapping("text"),
				"tags":           mapping("keyword"),
				"created_at":     mapping("date"),
				"updated_at":     mapping("date"),
			},
		},
	}
}

// DeleteDoc deletes a document by ID from the given index.
func (s *Store) DeleteDoc(ctx context.Context, index, id string) error {
	res, err := s.client.Delete(
		index,
		id,
		s.client.Delete.WithContext(ctx),
		s.client.Delete.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("delete doc: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("delete doc error: %s", res.String())
	}
	return nil
}
