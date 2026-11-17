package model

// ExecutionObservation describes invocation metadata, never code contents or
// proof that supplied code completed. Interpreter argv is discarded separately.
type ExecutionObservation struct {
	Runtime        string `json:"runtime" yaml:"runtime"`
	Mode           string `json:"mode" yaml:"mode"`
	Evidence       string `json:"evidence" yaml:"evidence"`
	Option         string `json:"option,omitempty" yaml:"option,omitempty"`
	ScriptLocation string `json:"script_location,omitempty" yaml:"script_location,omitempty"`
	PolicyName     string `json:"policy_name,omitempty" yaml:"policy_name,omitempty"`
}

// FileObservation records a bounded file operation. For vfs_write, a positive
// return is bytes written, zero is no_data, and a negative value is failed. A
// missing return is unknown; permission checks must never be called writes.
type FileObservation struct {
	Path        string `json:"path" yaml:"path"`
	Operation   string `json:"operation" yaml:"operation"`
	Outcome     string `json:"outcome" yaml:"outcome"`
	ReturnValue *int64 `json:"return_value,omitempty" yaml:"return_value,omitempty"`
	PolicyName  string `json:"policy_name" yaml:"policy_name"`
	Function    string `json:"function" yaml:"function"`
}

// NetworkObservation intentionally contains neither packet nor application
// contents. tcp_v4/v6_connect returning zero means initiated, not established.
type NetworkObservation struct {
	Operation          string `json:"operation" yaml:"operation"`
	Protocol           string `json:"protocol" yaml:"protocol"`
	Family             string `json:"family" yaml:"family"`
	DestinationAddress string `json:"destination_address" yaml:"destination_address"`
	DestinationPort    uint16 `json:"destination_port" yaml:"destination_port"`
	Outcome            string `json:"outcome" yaml:"outcome"`
	ReturnValue        *int64 `json:"return_value,omitempty" yaml:"return_value,omitempty"`
	PolicyName         string `json:"policy_name" yaml:"policy_name"`
	Function           string `json:"function" yaml:"function"`
}
