package rules

import (
	"encoding/json"
	"net/http"

	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// RuleLister provides access to loaded Sigma rules.
type RuleLister interface {
	Rules() []*correlate.SigmaRule
}

// Handler serves the rules listing endpoint.
type Handler struct {
	rulesDir     string
	logsourceMap string
}

// NewHandler creates a new rules handler.
func NewHandler(rulesDir, logsourceMapPath string) *Handler {
	return &Handler{rulesDir: rulesDir, logsourceMap: logsourceMapPath}
}

// ruleResponse is the JSON shape for a single rule in the list.
type ruleResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	Author        string `json:"author"`
	Tactic        string `json:"tactic,omitempty"`
	TechniqueID   string `json:"techniqueId,omitempty"`
	TechniqueName string `json:"techniqueName,omitempty"`
	Type          string `json:"type"`
	Enabled       bool   `json:"enabled"`
}

// HandleList handles GET /api/v1/rules.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	rules, _ := correlate.LoadRulesFromDir(h.rulesDir)

	resp := make([]ruleResponse, 0, len(rules))
	for _, rule := range rules {
		tactic, techniqueID, techniqueName := extractMITRE(rule.Tags)
		ruleType := "single"
		if rule.Type != "" {
			ruleType = rule.Type
		}
		resp = append(resp, ruleResponse{
			ID:            rule.ID,
			Name:          rule.Title,
			Description:   rule.Description,
			Severity:      rule.Level,
			Status:        rule.Status,
			Author:        rule.Author,
			Tactic:        tactic,
			TechniqueID:   techniqueID,
			TechniqueName: techniqueName,
			Type:          ruleType,
			Enabled:       true,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"rules": resp,
		"total": len(resp),
	})
}

// extractMITRE pulls tactic and technique from Sigma tags.
// Sigma convention: "attack.tactic_name", "attack.t1234.001"
func extractMITRE(tags []string) (tactic, techniqueID, techniqueName string) {
	for _, tag := range tags {
		if len(tag) > 7 && tag[:7] == "attack." {
			rest := tag[7:]
			if len(rest) > 0 && (rest[0] == 't' || rest[0] == 'T') && len(rest) >= 5 {
				// Technique ID like t1003.001 or T1059
				techniqueID = rest
			} else {
				// Tactic name like "credential_access"
				tactic = rest
			}
		}
	}
	return
}
