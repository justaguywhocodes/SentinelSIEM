package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derekxmartin/akeso-siem/internal/store"
)

// APIHandler serves the alerts listing and update endpoints.
type APIHandler struct {
	store  *store.Store
	prefix string
}

// NewAPIHandler creates a new alert API handler.
func NewAPIHandler(store *store.Store, prefix string) *APIHandler {
	return &APIHandler{store: store, prefix: prefix}
}

// Routes registers alert API routes.
func (h *APIHandler) Routes(r chi.Router) {
	r.Get("/api/v1/alerts", h.HandleList)
	r.Get("/api/v1/alerts/{id}", h.HandleGet)
	r.Patch("/api/v1/alerts/{index}/{id}", h.HandleUpdate)
	r.Post("/api/v1/alerts/bulk-update", h.HandleBulkUpdate)
}

// HandleList handles GET /api/v1/alerts.
func (h *APIHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	q := r.URL.Query()
	size, _ := strconv.Atoi(q.Get("size"))
	if size <= 0 || size > 10000 {
		size = 50
	}
	from, _ := strconv.Atoi(q.Get("from"))
	if from < 0 {
		from = 0
	}

	// Build ES query with optional filters.
	must := make([]map[string]any, 0)

	if sev := q.Get("severity"); sev != "" {
		must = append(must, map[string]any{"term": map[string]any{"event.severity": sev}})
	}
	if status := q.Get("status"); status != "" {
		must = append(must, map[string]any{"term": map[string]any{"event.outcome": status}})
	}

	query := map[string]any{"match_all": map[string]any{}}
	if len(must) > 0 {
		query = map[string]any{"bool": map[string]any{"must": must}}
	}

	alertsIdx := h.prefix + "-alerts-*"
	result, err := h.store.SearchRawWithMeta(ctx, alertsIdx, map[string]any{
		"query": query,
		"size":  size,
		"from":  from,
		"sort":  []map[string]any{{"@timestamp": map[string]string{"order": "desc"}}},
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"alerts": []any{},
			"total":  0,
			"from":   from,
			"size":   size,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"alerts": result.Hits,
		"total":  result.Total,
		"from":   from,
		"size":   size,
	})
}

// HandleGet handles GET /api/v1/alerts/{id} — fetches a single alert by _id across all alert indices.
func (h *APIHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	id := chi.URLParam(r, "id")
	alertsIdx := h.prefix + "-alerts-*"
	result, err := h.store.SearchRawWithMeta(ctx, alertsIdx, map[string]any{
		"query": map[string]any{"ids": map[string]any{"values": []string{id}}},
		"size":  1,
	})
	if err != nil || len(result.Hits) == 0 {
		http.Error(w, `{"error":"alert not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result.Hits[0])
}

// updateRequest is the JSON body for PATCH /api/v1/alerts/{index}/{id}.
type updateRequest struct {
	Status string `json:"status"`
}

// HandleUpdate handles PATCH /api/v1/alerts/{index}/{id}.
func (h *APIHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	index := chi.URLParam(r, "index")
	id := chi.URLParam(r, "id")

	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err := h.store.UpdateFields(ctx, index, id, map[string]any{
		"event": map[string]any{"outcome": req.Status},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// bulkUpdateRequest is the JSON body for POST /api/v1/alerts/bulk-update.
type bulkUpdateRequest struct {
	Alerts []bulkAlertRef `json:"alerts"`
	Status string         `json:"status"`
}

type bulkAlertRef struct {
	Index string `json:"_index"`
	ID    string `json:"_id"`
}

// HandleBulkUpdate handles POST /api/v1/alerts/bulk-update.
func (h *APIHandler) HandleBulkUpdate(w http.ResponseWriter, r *http.Request) {
	var req bulkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Status == "" || len(req.Alerts) == 0 {
		writeError(w, http.StatusBadRequest, "status and alerts are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	updated := 0
	var lastErr error
	for _, ref := range req.Alerts {
		err := h.store.UpdateFields(ctx, ref.Index, ref.ID, map[string]any{
			"event": map[string]any{"outcome": req.Status},
		})
		if err != nil {
			lastErr = err
		} else {
			updated++
		}
	}

	resp := map[string]any{"updated": updated, "total": len(req.Alerts)}
	if lastErr != nil {
		resp["error"] = lastErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
