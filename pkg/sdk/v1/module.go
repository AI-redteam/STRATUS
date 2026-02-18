// Package sdk provides the module developer interface for STRATUS plugins.
// Every module implements the Module interface and declares its metadata via ModuleMeta.
package sdk

// RiskClass constants for module classification.
const (
	RiskReadOnly    = "read_only"
	RiskWrite       = "write"
	RiskDestructive = "destructive"
)

// ModuleMeta declares everything the runtime needs to know about a module
// before loading or running it.
type ModuleMeta struct {
	ID                string              `json:"id"`       // e.g., com.stratus.iam.enumerate-roles
	Name              string              `json:"name"`     // Human-readable name
	Version           string              `json:"version"`  // semver
	Description       string              `json:"description"`
	Services          []string            `json:"services"`          // AWS services used
	RequiredActions   []string            `json:"required_actions"`  // IAM actions needed
	RequiredResources []string            `json:"required_resources"`
	RiskClass         string              `json:"risk_class"`
	Inputs            []InputSpec         `json:"inputs"`
	Outputs           []OutputSpec        `json:"outputs"`
	GraphMutations    []GraphMutationSpec `json:"graph_mutations,omitempty"`
	References        []string            `json:"references,omitempty"` // MITRE ATT&CK, CVEs
	UIHints           UIHintSpec          `json:"ui_hints,omitempty"`
	Author            string              `json:"author"`
	Signature         string              `json:"signature,omitempty"` // Ed25519 over content hash
	MinStratusVersion string              `json:"min_stratus_version,omitempty"`
}

// InputSpec describes a module input parameter.
type InputSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string | int | bool | []string | etc.
	Default     any    `json:"default,omitempty"`
	Description string `json:"description"`
	Required    bool   `json:"required,omitempty"`
}

// OutputSpec describes a module output field.
type OutputSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// GraphMutationSpec declares what graph edges a module will create or modify.
type GraphMutationSpec struct {
	EdgeType      string `json:"edge_type"`
	SourcePattern string `json:"source_pattern"`
	TargetPattern string `json:"target_pattern"`
}

// UIHintSpec provides rendering hints for the GUI.
type UIHintSpec struct {
	Category    string `json:"category,omitempty"`    // IAM, S3, EC2, etc.
	IconName    string `json:"icon_name,omitempty"`
	Color       string `json:"color,omitempty"`
	SortOrder   int    `json:"sort_order,omitempty"`
}

// SessionSnapshot is an immutable copy of a session's non-secret state.
type SessionSnapshot struct {
	UUID           string  `json:"uuid"`
	IdentityUUID   string  `json:"identity_uuid"`
	AWSAccessKeyID string  `json:"aws_access_key_id"`
	SessionName    string  `json:"session_name"`
	Region         string  `json:"region"`
	Expiry         *string `json:"expiry,omitempty"`
	HealthStatus   string  `json:"health_status"`
	WorkspaceUUID  string  `json:"workspace_uuid"`
}

// RunContext provides modules with everything they need for execution.
type RunContext struct {
	Session   SessionSnapshot
	Inputs    map[string]any
	RunID     string
	DryRun    bool
}

// InputString is a helper to get a string input with default handling.
func (ctx RunContext) InputString(name string) string {
	if v, ok := ctx.Inputs[name]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// InputInt is a helper to get an int input with default handling.
func (ctx RunContext) InputInt(name string) int {
	if v, ok := ctx.Inputs[name]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return 0
}

// InputBool is a helper to get a bool input with default handling.
func (ctx RunContext) InputBool(name string) bool {
	if v, ok := ctx.Inputs[name]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// PreflightResult reports whether the module's permission requirements are met.
type PreflightResult struct {
	MissingPermissions []string `json:"missing_permissions,omitempty"`
	PlannedAPICalls    []string `json:"planned_api_calls"`
	Confidence         float64  `json:"confidence"`
	Warnings           []string `json:"warnings,omitempty"`
}

// DryRunResult describes what a module would do without executing.
type DryRunResult struct {
	Description string `json:"description"`
	WouldMutate bool   `json:"would_mutate"`
	APICalls    []string `json:"api_calls,omitempty"`
}

// RunResult is the output of a module execution.
type RunResult struct {
	Outputs    map[string]any `json:"outputs,omitempty"`
	Error      error          `json:"-"`
	ErrorMsg   string         `json:"error,omitempty"`
}

// ErrResult creates a RunResult from an error.
func ErrResult(err error) RunResult {
	return RunResult{Error: err, ErrorMsg: err.Error()}
}

// Progress reports execution progress.
type Progress interface {
	Update(current int, message string)
	Total(total int)
}

// PriorRunRecord contains information from a previous run for replay.
type PriorRunRecord struct {
	RunID   string         `json:"run_id"`
	Inputs  map[string]any `json:"inputs"`
	Outputs map[string]any `json:"outputs"`
}

// Module is the interface that all STRATUS modules must implement.
type Module interface {
	Meta() ModuleMeta
	Preflight(ctx RunContext) PreflightResult
	DryRun(ctx RunContext) DryRunResult
	Run(ctx RunContext, progress Progress) RunResult
	Replay(ctx RunContext, prior PriorRunRecord) RunResult
}

// ConfidenceFromMissing calculates a confidence score based on missing permissions.
func ConfidenceFromMissing(missing []string) float64 {
	if len(missing) == 0 {
		return 1.0
	}
	return 0.0
}

// NoOpProgress is a progress reporter that discards updates.
type noOpProgress struct{}

func (noOpProgress) Update(int, string) {}
func (noOpProgress) Total(int)          {}

// NoOpProgress is a singleton no-op progress reporter.
var NoOpProgress Progress = noOpProgress{}
