package privileges

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Tetragon's protojson CLI omits an empty repeated policies field, producing
// {}. Only an empty object or one explicit policies array represents a list;
// null, unknown envelopes and ambiguous duplicate keys are not an empty list.
func decodePolicyList(data []byte) ([]policyState, error) {
	invalid := errors.New("invalid policy list")
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !uniquePolicyJSONValue(decoder, 0) {
		return nil, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || envelope == nil {
		return nil, invalid
	}
	if len(envelope) == 0 {
		return []policyState{}, nil
	}
	raw, exists := envelope["policies"]
	if !exists || len(envelope) != 1 {
		return nil, invalid
	}
	var policies []*policyState
	if json.Unmarshal(raw, &policies) != nil || policies == nil || len(policies) > 256 {
		return nil, invalid
	}
	result := make([]policyState, 0, len(policies))
	for _, p := range policies {
		if p == nil || p.Name == "" {
			return nil, invalid
		}
		result = append(result, *p)
	}
	return result, nil
}

// encoding/json normally accepts duplicate object keys with last-value wins.
// Reject them at every depth before interpreting policy identity or readiness.
func uniquePolicyJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return false
			}
			seen[key] = true
			if !uniquePolicyJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !uniquePolicyJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
