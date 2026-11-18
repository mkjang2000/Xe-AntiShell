package webpanel

import (
	"encoding/json"
	"io"
	"net/http"

	"xe-antishell/internal/detection"
)

// Bundled labels also identify findings while the agent is unavailable or older
// than the catalog API. Only the agent can supply current policy and sensor state.
func writeRuleDefinitions(w io.Writer) error {
	type label struct {
		ID          string `json:"id"`
		Profile     string `json:"profile"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	definitions := detection.RuleDefinitions()
	labels := make([]label, 0, len(definitions))
	for _, rule := range definitions {
		labels = append(labels, label{rule.ID, rule.Profile, rule.Title, rule.Description})
	}
	if _, err := io.WriteString(w, "const bundledRuleDefinitions = "); err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(labels)
}

func serveRuleDefinitions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_ = writeRuleDefinitions(w)
}
