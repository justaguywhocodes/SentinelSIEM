package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/store"
)

// Handler serves the dashboard overview endpoint.
type Handler struct {
	store  *store.Store
	prefix string
}

// NewHandler creates a new dashboard handler.
func NewHandler(store *store.Store, prefix string) *Handler {
	return &Handler{store: store, prefix: prefix}
}

// HandleOverview handles GET /api/v1/dashboard/overview.
func (h *Handler) HandleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp := map[string]any{
		"kpis":         h.fetchKPIs(ctx),
		"alertTrend":   h.fetchAlertTrend(ctx),
		"topRules":     h.fetchTopRules(ctx),
		"sourceHealth": h.fetchSourceHealth(ctx),
		"ndrHostRisk":  h.fetchNDRHostRisk(ctx),
		"ndrSummary":   h.fetchNDRSummary(ctx),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) fetchKPIs(ctx context.Context) map[string]any {
	eventsIdx := h.prefix + "-events-*"
	alertsIdx := h.prefix + "-alerts-*"
	sourcesIdx := h.prefix + "-sources"

	// Events per second: count events in last 60s, divide by 60.
	eps := 0.0
	epsResult, err := h.store.SearchRaw(ctx, eventsIdx, map[string]any{
		"size": 0,
		"query": map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{
					"gte": "now-60s",
				},
			},
		},
	})
	if err == nil {
		eps = float64(epsResult.Total) / 60.0
	}

	// Open alerts with severity breakdown.
	openAlerts := 0
	severityDots := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	alertResult, err := h.store.SearchRaw(ctx, alertsIdx, map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must_not": []map[string]any{
					{"term": map[string]any{"event.outcome": "closed"}},
				},
			},
		},
		"aggs": map[string]any{
			"by_severity": map[string]any{
				"terms": map[string]any{
					"field": "event.severity",
					"size":  10,
				},
			},
		},
	})
	if err == nil {
		openAlerts = alertResult.Total
		if alertResult.Aggs != nil {
			var aggs struct {
				BySeverity struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"by_severity"`
			}
			if json.Unmarshal(alertResult.Aggs, &aggs) == nil {
				for _, b := range aggs.BySeverity.Buckets {
					severityDots[b.Key] = b.DocCount
				}
			}
		}
	}

	// Source health: count sources.
	totalSources := 0
	activeSources := 0
	srcResult, err := h.store.SearchRaw(ctx, sourcesIdx, map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_status": map[string]any{
				"terms": map[string]any{
					"field": "status.keyword",
					"size":  10,
				},
			},
		},
	})
	if err == nil {
		totalSources = srcResult.Total
		if srcResult.Aggs != nil {
			var aggs struct {
				ByStatus struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"by_status"`
			}
			if json.Unmarshal(srcResult.Aggs, &aggs) == nil {
				for _, b := range aggs.ByStatus.Buckets {
					if b.Key == "active" {
						activeSources = b.DocCount
					}
				}
			}
		}
	}

	return map[string]any{
		"eventsPerSec": map[string]any{
			"label":    "Events/sec",
			"value":    int(eps),
			"change":   0,
			"sparkline": []any{},
		},
		"openAlerts": map[string]any{
			"label":        "Open Alerts",
			"value":        openAlerts,
			"change":       0,
			"sparkline":    []any{},
			"severityDots": severityDots,
		},
		"mttd": map[string]any{
			"label":    "MTTD",
			"value":    "0m",
			"change":   0,
			"sparkline": []any{},
		},
		"mttr": map[string]any{
			"label":    "MTTR",
			"value":    "0m",
			"change":   0,
			"sparkline": []any{},
		},
		"sourceHealth": map[string]any{
			"label":    "Source Health",
			"value":    intToFraction(activeSources, totalSources),
			"change":   0,
			"sparkline": []any{},
			"gauge":    map[string]int{"active": activeSources, "expected": totalSources},
		},
	}
}

func intToFraction(a, b int) string {
	return fmt.Sprintf("%d/%d", a, b)
}


func (h *Handler) fetchAlertTrend(ctx context.Context) []map[string]any {
	alertsIdx := h.prefix + "-alerts-*"

	result, err := h.store.SearchRaw(ctx, alertsIdx, map[string]any{
		"size": 0,
		"query": map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": "now-24h"},
			},
		},
		"aggs": map[string]any{
			"by_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":          "@timestamp",
					"fixed_interval": "1h",
				},
				"aggs": map[string]any{
					"by_severity": map[string]any{
						"terms": map[string]any{
							"field": "event.severity",
							"size":  10,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return make([]map[string]any, 0)
	}

	var aggs struct {
		ByHour struct {
			Buckets []struct {
				KeyAsString string `json:"key_as_string"`
				BySeverity  struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"by_severity"`
			} `json:"buckets"`
		} `json:"by_hour"`
	}
	if result.Aggs == nil || json.Unmarshal(result.Aggs, &aggs) != nil {
		return make([]map[string]any, 0)
	}

	trend := make([]map[string]any, 0, len(aggs.ByHour.Buckets))
	for _, bucket := range aggs.ByHour.Buckets {
		entry := map[string]any{
			"time":     bucket.KeyAsString,
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		}
		for _, sev := range bucket.BySeverity.Buckets {
			entry[sev.Key] = sev.DocCount
		}
		trend = append(trend, entry)
	}
	return trend
}

func (h *Handler) fetchTopRules(ctx context.Context) []map[string]any {
	alertsIdx := h.prefix + "-alerts-*"

	result, err := h.store.SearchRaw(ctx, alertsIdx, map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"top_rules": map[string]any{
				"terms": map[string]any{
					"field": "rule.name.keyword",
					"size":  10,
				},
				"aggs": map[string]any{
					"severity": map[string]any{
						"terms": map[string]any{
							"field": "event.severity",
							"size":  1,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return make([]map[string]any, 0)
	}

	var aggs struct {
		TopRules struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int    `json:"doc_count"`
				Severity struct {
					Buckets []struct {
						Key string `json:"key"`
					} `json:"buckets"`
				} `json:"severity"`
			} `json:"buckets"`
		} `json:"top_rules"`
	}
	if result.Aggs == nil || json.Unmarshal(result.Aggs, &aggs) != nil {
		return make([]map[string]any, 0)
	}

	rules := make([]map[string]any, 0, len(aggs.TopRules.Buckets))
	for _, b := range aggs.TopRules.Buckets {
		sev := "medium"
		if len(b.Severity.Buckets) > 0 {
			sev = b.Severity.Buckets[0].Key
		}
		rules = append(rules, map[string]any{
			"rule":     b.Key,
			"count":    b.DocCount,
			"severity": sev,
		})
	}
	return rules
}

func (h *Handler) fetchSourceHealth(ctx context.Context) []map[string]any {
	sourcesIdx := h.prefix + "-sources"

	result, err := h.store.Search(ctx, sourcesIdx, map[string]any{
		"match_all": map[string]any{},
	}, 100)
	if err != nil {
		return make([]map[string]any, 0)
	}

	sources := make([]map[string]any, 0, len(result.Hits))
	for _, hit := range result.Hits {
		var src map[string]any
		if json.Unmarshal(hit, &src) == nil {
			sources = append(sources, map[string]any{
				"name":      src["name"],
				"type":      src["type"],
				"status":    mapSourceStatus(src["status"]),
				"eps":       0,
				"lastEvent": "",
			})
		}
	}
	return sources
}

func mapSourceStatus(status any) string {
	s, ok := status.(string)
	if !ok {
		return "error"
	}
	switch s {
	case "active":
		return "healthy"
	case "disabled":
		return "degraded"
	default:
		return "error"
	}
}

func (h *Handler) fetchNDRHostRisk(ctx context.Context) []map[string]any {
	ndrIdx := h.prefix + "-ndr-host-scores"

	result, err := h.store.SearchRaw(ctx, ndrIdx, map[string]any{
		"size": 10,
		"query": map[string]any{
			"bool": map[string]any{
				"should": []map[string]any{
					{"term": map[string]any{"ndr.host_score.quadrant": "critical"}},
					{"term": map[string]any{"ndr.host_score.quadrant": "high"}},
				},
				"minimum_should_match": 1,
			},
		},
		"sort": []map[string]any{
			{"ndr.host_score.threat": map[string]string{"order": "desc"}},
		},
	})
	if err != nil {
		return make([]map[string]any, 0)
	}

	hosts := make([]map[string]any, 0, len(result.Hits))
	for _, hit := range result.Hits {
		var doc map[string]any
		if json.Unmarshal(hit, &doc) == nil {
			hosts = append(hosts, doc)
		}
	}
	return hosts
}

func (h *Handler) fetchNDRSummary(ctx context.Context) map[string]any {
	ndrIdx := h.prefix + "-ndr-host-scores"

	result, err := h.store.SearchRaw(ctx, ndrIdx, map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_quadrant": map[string]any{
				"terms": map[string]any{
					"field": "ndr.host_score.quadrant",
					"size":  10,
				},
			},
		},
	})

	summary := map[string]any{
		"totalMonitored": 0,
		"critical":       0,
		"high":           0,
		"medium":         0,
		"low":            0,
	}

	if err != nil {
		return summary
	}

	summary["totalMonitored"] = result.Total

	if result.Aggs != nil {
		var aggs struct {
			ByQuadrant struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_quadrant"`
		}
		if json.Unmarshal(result.Aggs, &aggs) == nil {
			for _, b := range aggs.ByQuadrant.Buckets {
				summary[b.Key] = b.DocCount
			}
		}
	}
	return summary
}
