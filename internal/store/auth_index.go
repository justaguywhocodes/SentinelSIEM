package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// UserIndexName returns the dedicated user index name.
func (s *Store) UserIndexName() string {
	return s.prefix + "-users"
}

// SessionIndexName returns the dedicated session index name.
func (s *Store) SessionIndexName() string {
	return s.prefix + "-sessions"
}

// EnsureUserIndex creates the dedicated user index with mappings if it doesn't exist.
func (s *Store) EnsureUserIndex(ctx context.Context) error {
	indexName := s.UserIndexName()

	res, err := s.client.Indices.Exists([]string{indexName},
		s.client.Indices.Exists.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("checking user index: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		return nil
	}

	mappings := userIndexMappings()
	body, err := json.Marshal(mappings)
	if err != nil {
		return fmt.Errorf("marshaling user index mappings: %w", err)
	}

	res, err = s.client.Indices.Create(
		indexName,
		s.client.Indices.Create.WithContext(ctx),
		s.client.Indices.Create.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return fmt.Errorf("creating user index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("user index creation: %s", res.String())
	}

	return nil
}

// EnsureSessionIndex creates the dedicated session index with mappings if it doesn't exist.
func (s *Store) EnsureSessionIndex(ctx context.Context) error {
	indexName := s.SessionIndexName()

	res, err := s.client.Indices.Exists([]string{indexName},
		s.client.Indices.Exists.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("checking session index: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		return nil
	}

	mappings := sessionIndexMappings()
	body, err := json.Marshal(mappings)
	if err != nil {
		return fmt.Errorf("marshaling session index mappings: %w", err)
	}

	res, err = s.client.Indices.Create(
		indexName,
		s.client.Indices.Create.WithContext(ctx),
		s.client.Indices.Create.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return fmt.Errorf("creating session index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("session index creation: %s", res.String())
	}

	return nil
}

// CountDocs returns the count of documents matching a query in the given index.
func (s *Store) CountDocs(ctx context.Context, index string, query map[string]any) (int64, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return 0, fmt.Errorf("marshaling count query: %w", err)
	}

	res, err := s.client.Count(
		s.client.Count.WithContext(ctx),
		s.client.Count.WithIndex(index),
		s.client.Count.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return 0, fmt.Errorf("count request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return 0, fmt.Errorf("count error: %s", res.String())
	}

	var result struct {
		Count int64 `json:"count"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decoding count response: %w", err)
	}

	return result.Count, nil
}

func userIndexMappings() map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"id":            mapping("keyword"),
				"username":      mapping("keyword"),
				"display_name":  mapping("keyword"),
				"email":         mapping("keyword"),
				"password_hash": map[string]any{"type": "keyword", "index": false},
				"role":          mapping("keyword"),
				"mfa_enabled":   mapping("boolean"),
				"mfa_secret":    map[string]any{"type": "keyword", "index": false},
				"disabled":      mapping("boolean"),
				"created_at":    mapping("date"),
				"updated_at":    mapping("date"),
				"last_login_at": mapping("date"),
			},
		},
	}
}

func sessionIndexMappings() map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"id":         mapping("keyword"),
				"user_id":    mapping("keyword"),
				"token_hash": map[string]any{"type": "keyword", "index": false},
				"created_at": mapping("date"),
				"expires_at": mapping("date"),
				"revoked":    mapping("boolean"),
				"revoked_at": mapping("date"),
				"user_agent": mapping("keyword"),
				"ip":         mapping("keyword"),
			},
		},
	}
}
