package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// CaseIndexName returns the dedicated case index name.
func (s *Store) CaseIndexName() string {
	return s.prefix + "-cases"
}

// EnsureCaseIndex creates the dedicated case index with mappings and ILM policy if they don't exist.
func (s *Store) EnsureCaseIndex(ctx context.Context) error {
	// Ensure ILM policy exists first.
	if err := s.ensureCaseILMPolicy(ctx); err != nil {
		return fmt.Errorf("ensuring case ILM policy: %w", err)
	}

	indexName := s.CaseIndexName()

	res, err := s.client.Indices.Exists([]string{indexName},
		s.client.Indices.Exists.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("checking case index: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		return nil
	}

	mappings := caseIndexMappings(s.caseILMPolicyName())
	body, err := json.Marshal(mappings)
	if err != nil {
		return fmt.Errorf("marshaling case index mappings: %w", err)
	}

	res, err = s.client.Indices.Create(
		indexName,
		s.client.Indices.Create.WithContext(ctx),
		s.client.Indices.Create.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return fmt.Errorf("creating case index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("case index creation: %s", res.String())
	}

	return nil
}

// caseILMPolicyName returns the ILM policy name for the case index.
func (s *Store) caseILMPolicyName() string {
	return s.prefix + "-cases-ilm-policy"
}

// ensureCaseILMPolicy creates the ILM policy for cases (365-day retention) if it doesn't exist.
func (s *Store) ensureCaseILMPolicy(ctx context.Context) error {
	policyName := s.caseILMPolicyName()

	policy := map[string]any{
		"policy": map[string]any{
			"phases": map[string]any{
				"delete": map[string]any{
					"min_age": "365d",
					"actions": map[string]any{
						"delete": map[string]any{},
					},
				},
			},
		},
	}

	body, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshaling case ILM policy: %w", err)
	}

	res, err := s.client.ILM.PutLifecycle(
		policyName,
		s.client.ILM.PutLifecycle.WithContext(ctx),
		s.client.ILM.PutLifecycle.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return fmt.Errorf("creating case ILM policy: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("case ILM policy creation: %s", res.String())
	}

	return nil
}

// caseIndexMappings returns the index creation body with field mappings
// for the dedicated case management index.
func caseIndexMappings(ilmPolicyName string) map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":     1,
			"number_of_replicas":   0,
			"index.lifecycle.name": ilmPolicyName,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				// Core case fields.
				"id":       mapping("keyword"),
				"title":    map[string]any{"type": "text", "fields": map[string]any{"keyword": mapping("keyword")}},
				"status":   mapping("keyword"),
				"severity": mapping("keyword"),
				"assignee": mapping("keyword"),
				"tags":     mapping("keyword"),

				// Linked alert IDs.
				"alert_ids": mapping("keyword"),

				// Observables (nested for independent querying).
				"observables": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"type":   mapping("keyword"),
						"value":  mapping("keyword"),
						"source": mapping("keyword"),
						"tags":   mapping("keyword"),
					},
				},

				// Timeline entries (nested for independent querying).
				"timeline": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"timestamp":   mapping("date"),
						"author":      mapping("keyword"),
						"action_type": mapping("keyword"),
						"content":     map[string]any{"type": "object", "enabled": false},
					},
				},

				// Resolution (set on close).
				"resolution": map[string]any{
					"properties": map[string]any{
						"type":  mapping("keyword"),
						"notes": mapping("text"),
					},
				},

				// Timestamps.
				"created_at": mapping("date"),
				"updated_at": mapping("date"),
				"closed_at":  mapping("date"),
			},
		},
	}
}
