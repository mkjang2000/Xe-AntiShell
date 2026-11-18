package collector

import "encoding/json"

// tetragonCapabilityList interns only fully recognized, unescaped source enum
// arrays. All other input retains encoding/json's []string decoding semantics;
// the normalizer still decides which capability values are supported.
type tetragonCapabilityList []string

func (values *tetragonCapabilityList) UnmarshalJSON(raw []byte) error {
	if values != nil {
		if decoded, ok := knownTetragonCapabilityArray(raw); ok {
			*values = decoded
			return nil
		}
	}
	return json.Unmarshal(raw, (*[]string)(values))
}

func knownTetragonCapabilityArray(raw []byte) (tetragonCapabilityList, bool) {
	position := capabilityJSONSpace(raw, 0)
	if position == len(raw) || raw[position] != '[' {
		return nil, false
	}
	position = capabilityJSONSpace(raw, position+1)
	var scratch [64]string
	count := 0
	if position < len(raw) && raw[position] == ']' {
		if capabilityJSONSpace(raw, position+1) == len(raw) {
			return make(tetragonCapabilityList, 0), true
		}
		return nil, false
	}
	for {
		if count == len(scratch) || position == len(raw) || raw[position] != '"' {
			return nil, false
		}
		position++
		start := position
		for position < len(raw) && raw[position] != '"' {
			value := raw[position]
			if value == '\\' || value < 0x20 || value >= 0x80 {
				return nil, false
			}
			position++
		}
		if position == len(raw) {
			return nil, false
		}
		token := raw[start:position]
		value, known := tetragonCapabilityNames[string(token)]
		if !known {
			if string(token) != "DAC_OVERRIDE" {
				return nil, false
			}
			// Preserve the upstream spelling until the existing normalizer runs.
			value = "DAC_OVERRIDE"
		}
		scratch[count] = value
		count++
		position = capabilityJSONSpace(raw, position+1)
		if position == len(raw) {
			return nil, false
		}
		switch raw[position] {
		case ',':
			position = capabilityJSONSpace(raw, position+1)
		case ']':
			if capabilityJSONSpace(raw, position+1) != len(raw) {
				return nil, false
			}
			decoded := make(tetragonCapabilityList, count)
			copy(decoded, scratch[:count])
			return decoded, true
		default:
			return nil, false
		}
	}
}

func capabilityJSONSpace(raw []byte, position int) int {
	for position < len(raw) {
		switch raw[position] {
		case ' ', '\t', '\n', '\r':
			position++
		default:
			return position
		}
	}
	return position
}
