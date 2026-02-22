// Package module implements the module registry and execution engine.
// For MVP, modules are built-in Go structs registered at startup.
// Plugin-based loading (.so/.dylib) is planned for a future release.
package module

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stratus-framework/stratus/internal/artifact"
	"github.com/stratus-framework/stratus/internal/audit"
	stratusaws "github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	"github.com/stratus-framework/stratus/internal/scope"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// Registry holds all available modules and manages execution.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]sdk.Module
	db      *sql.DB
	logger  zerolog.Logger
}

// NewRegistry creates a module registry.
func NewRegistry(db *sql.DB, logger zerolog.Logger) *Registry {
	return &Registry{
		modules: make(map[string]sdk.Module),
		db:      db,
		logger:  logger,
	}
}

// Register adds a module to the registry.
func (r *Registry) Register(mod sdk.Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	meta := mod.Meta()
	r.modules[meta.ID] = mod
	r.logger.Debug().Str("module", meta.ID).Str("version", meta.Version).Msg("module registered")
}

// Get returns a module by ID.
func (r *Registry) Get(id string) (sdk.Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mod, ok := r.modules[id]
	return mod, ok
}

// List returns all registered module metadata.
func (r *Registry) List() []sdk.ModuleMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var metas []sdk.ModuleMeta
	for _, mod := range r.modules {
		metas = append(metas, mod.Meta())
	}
	return metas
}

// Search returns modules matching the given criteria.
func (r *Registry) Search(keyword, service, riskClass, tag string) []sdk.ModuleMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keyword = strings.ToLower(keyword)
	service = strings.ToLower(service)
	riskClass = strings.ToLower(riskClass)
	tag = strings.ToLower(tag)

	var results []sdk.ModuleMeta
	for _, mod := range r.modules {
		meta := mod.Meta()
		if !matchesFilter(meta, keyword, service, riskClass, tag) {
			continue
		}
		results = append(results, meta)
	}
	return results
}

func matchesFilter(meta sdk.ModuleMeta, keyword, service, riskClass, tag string) bool {
	if keyword != "" {
		haystack := strings.ToLower(meta.ID + " " + meta.Name + " " + meta.Description)
		if !strings.Contains(haystack, keyword) {
			return false
		}
	}
	if service != "" {
		found := false
		for _, s := range meta.Services {
			if strings.ToLower(s) == service {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if riskClass != "" && strings.ToLower(meta.RiskClass) != riskClass {
		return false
	}
	if tag != "" {
		found := false
		for _, ref := range meta.References {
			if strings.Contains(strings.ToLower(ref), tag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Runner executes modules and records their results.
type Runner struct {
	registry       *Registry
	db             *sql.DB
	audit          *audit.Logger
	factory        *stratusaws.ClientFactory
	graphStore     *graph.Store
	logger         zerolog.Logger
	workspace      string
	scopeChecker   *scope.Checker
	artifactStore  *artifact.Store
}

// SetScope enables scope enforcement on the runner.
// When set, Execute() will reject operations targeting out-of-scope regions or accounts.
func (r *Runner) SetScope(checker *scope.Checker) {
	r.scopeChecker = checker
}

// SetArtifactStore enables automatic artifact storage for module outputs.
func (r *Runner) SetArtifactStore(store *artifact.Store) {
	r.artifactStore = store
}

// NewRunner creates a module execution runner.
func NewRunner(reg *Registry, db *sql.DB, al *audit.Logger, factory *stratusaws.ClientFactory, gs *graph.Store, logger zerolog.Logger, workspaceUUID string) *Runner {
	return &Runner{
		registry:  reg,
		db:        db,
		audit:     al,
		factory:   factory,
		graphStore: gs,
		logger:    logger,
		workspace: workspaceUUID,
	}
}

// RunConfig holds configuration for a module execution.
type RunConfig struct {
	ModuleID  string
	Inputs    map[string]any
	Session   *core.SessionRecord
	Creds     stratusaws.SessionCredentials
	DryRun    bool
	Operator  string
}

// Execute runs a module and records the result.
func (r *Runner) Execute(ctx context.Context, cfg RunConfig) (*core.ModuleRun, error) {
	// Scope enforcement: block out-of-scope operations before execution
	if r.scopeChecker != nil {
		if err := r.scopeChecker.CheckRegion(cfg.Creds.Region); err != nil {
			r.audit.Log(audit.EventScopeViolation, cfg.Operator, cfg.Session.UUID, "", map[string]string{
				"module_id": cfg.ModuleID,
				"region":    cfg.Creds.Region,
				"violation": err.Error(),
			})
			return nil, fmt.Errorf("scope violation: %w", err)
		}

		// Account scope check: resolve account ID from identity
		var accountID string
		r.db.QueryRow("SELECT account_id FROM identities WHERE uuid = ?", cfg.Session.IdentityUUID).Scan(&accountID)
		if accountID != "" {
			if err := r.scopeChecker.CheckAccount(accountID); err != nil {
				r.audit.Log(audit.EventScopeViolation, cfg.Operator, cfg.Session.UUID, "", map[string]string{
					"module_id":  cfg.ModuleID,
					"account_id": accountID,
					"violation":  err.Error(),
				})
				return nil, fmt.Errorf("scope violation: %w", err)
			}
		}
	}

	mod, ok := r.registry.Get(cfg.ModuleID)
	if !ok {
		return nil, fmt.Errorf("module not found: %s", cfg.ModuleID)
	}

	meta := mod.Meta()
	runID := uuid.New().String()
	now := time.Now().UTC()

	// Populate defaults for unset inputs
	inputs := make(map[string]any)
	for _, spec := range meta.Inputs {
		if v, ok := cfg.Inputs[spec.Name]; ok {
			inputs[spec.Name] = v
		} else if spec.Default != nil {
			inputs[spec.Name] = spec.Default
		}
	}

	run := &core.ModuleRun{
		UUID:            runID,
		ModuleID:        meta.ID,
		ModuleVersion:   meta.Version,
		SessionUUID:     cfg.Session.UUID,
		SessionSnapshot: *cfg.Session,
		Inputs:          inputs,
		Status:          core.RunPending,
		StartedAt:       now,
		WorkspaceUUID:   r.workspace,
		CreatedBy:       cfg.Operator,
	}

	// Persist run record
	if err := r.saveRun(run); err != nil {
		return nil, fmt.Errorf("saving run record: %w", err)
	}

	// Build RunContext
	runCtx := sdk.RunContext{
		Session: sdk.SessionSnapshot{
			UUID:           cfg.Session.UUID,
			IdentityUUID:   cfg.Session.IdentityUUID,
			AWSAccessKeyID: cfg.Session.AWSAccessKeyID,
			SessionName:    cfg.Session.SessionName,
			Region:         cfg.Session.Region,
			HealthStatus:   string(cfg.Session.HealthStatus),
			WorkspaceUUID:  cfg.Session.WorkspaceUUID,
		},
		Inputs: inputs,
		RunID:  runID,
		DryRun: cfg.DryRun,
	}

	if cfg.Session.Expiry != nil {
		exp := cfg.Session.Expiry.Format(time.RFC3339)
		runCtx.Session.Expiry = &exp
	}

	// Preflight check
	preflight := mod.Preflight(runCtx)
	if len(preflight.MissingPermissions) > 0 {
		r.logger.Warn().Strs("missing", preflight.MissingPermissions).Msg("preflight: missing permissions")
	}

	// Mandatory dry-run for write/destructive modules: log the plan to audit
	if meta.RiskClass == sdk.RiskWrite || meta.RiskClass == sdk.RiskDestructive {
		dryResult := mod.DryRun(runCtx)
		r.audit.Log(audit.EventModuleRun, cfg.Operator, cfg.Session.UUID, runID, map[string]string{
			"module_id":  meta.ID,
			"risk_class": meta.RiskClass,
			"action":     "mandatory_dry_run",
			"plan":       dryResult.Description,
		})
	}

	// Dry run mode
	if cfg.DryRun {
		dryResult := mod.DryRun(runCtx)
		run.Status = core.RunDryRun
		completedAt := time.Now().UTC()
		run.CompletedAt = &completedAt
		run.Outputs = map[string]any{
			"dry_run_description": dryResult.Description,
			"would_mutate":       dryResult.WouldMutate,
			"planned_api_calls":  dryResult.APICalls,
		}
		r.updateRun(run)
		return run, nil
	}

	// Execute
	run.Status = core.RunRunning
	r.updateRun(run)

	r.audit.Log(audit.EventModuleRun, cfg.Operator, cfg.Session.UUID, runID, map[string]string{
		"module_id":  meta.ID,
		"risk_class": meta.RiskClass,
		"action":     "started",
	})

	// Set resolved credentials on the factory so modules can create
	// region-only creds and the factory fills in the secret material.
	r.factory.SetDefaultCredentials(cfg.Creds)

	// Create a module-aware context that carries the AWS factory and graph store
	modCtx := &moduleExecContext{
		RunContext: runCtx,
		factory:   r.factory,
		creds:     cfg.Creds,
		graph:     r.graphStore,
	}

	result := mod.Run(modCtx.RunContext, &progressReporter{logger: r.logger, runID: runID})

	completedAt := time.Now().UTC()
	run.CompletedAt = &completedAt

	if result.Error != nil {
		run.Status = core.RunError
		errMsg := result.Error.Error()
		run.ErrorDetail = &errMsg
	} else {
		run.Status = core.RunSuccess
		run.Outputs = result.Outputs

		// Store outputs as artifact
		if r.artifactStore != nil && len(result.Outputs) > 0 {
			outputJSON, _ := json.MarshalIndent(result.Outputs, "", "  ")
			art, artErr := r.artifactStore.Create(artifact.CreateInput{
				RunUUID:      &runID,
				SessionUUID:  cfg.Session.UUID,
				ArtifactType: core.ArtifactJSONResult,
				Label:        fmt.Sprintf("%s output", meta.ID),
				Content:      outputJSON,
				CreatedBy:    cfg.Operator,
				Tags:         []string{"auto", meta.ID},
			})
			if artErr != nil {
				r.logger.Warn().Err(artErr).Str("run", runID).Msg("failed to store output artifact")
			} else {
				run.ArtifactUUIDs = append(run.ArtifactUUIDs, art.UUID)
			}
		}
	}

	r.updateRun(run)

	r.audit.Log(audit.EventModuleRun, cfg.Operator, cfg.Session.UUID, runID, map[string]string{
		"module_id":  meta.ID,
		"risk_class": meta.RiskClass,
		"action":     "completed",
		"status":     string(run.Status),
	})

	return run, nil
}

// Preflight runs the preflight check without executing.
func (r *Runner) Preflight(cfg RunConfig) (*sdk.PreflightResult, error) {
	mod, ok := r.registry.Get(cfg.ModuleID)
	if !ok {
		return nil, fmt.Errorf("module not found: %s", cfg.ModuleID)
	}

	meta := mod.Meta()
	inputs := make(map[string]any)
	for _, spec := range meta.Inputs {
		if v, ok := cfg.Inputs[spec.Name]; ok {
			inputs[spec.Name] = v
		} else if spec.Default != nil {
			inputs[spec.Name] = spec.Default
		}
	}

	runCtx := sdk.RunContext{
		Session: sdk.SessionSnapshot{
			UUID:           cfg.Session.UUID,
			AWSAccessKeyID: cfg.Session.AWSAccessKeyID,
			SessionName:    cfg.Session.SessionName,
			Region:         cfg.Session.Region,
		},
		Inputs: inputs,
		DryRun: true,
	}

	result := mod.Preflight(runCtx)
	return &result, nil
}

// ListRuns returns module runs for the workspace.
func (r *Runner) ListRuns(moduleFilter, statusFilter string) ([]core.ModuleRun, error) {
	query := `SELECT uuid, module_id, module_version, session_uuid, inputs, status,
	           started_at, completed_at, outputs, error_detail, workspace_uuid, created_by
	           FROM module_runs WHERE workspace_uuid = ?`
	args := []any{r.workspace}

	if moduleFilter != "" {
		query += " AND module_id = ?"
		args = append(args, moduleFilter)
	}
	if statusFilter != "" {
		query += " AND status = ?"
		args = append(args, statusFilter)
	}
	query += " ORDER BY started_at DESC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying runs: %w", err)
	}
	defer rows.Close()

	return scanRuns(rows)
}

// GetRun returns a single run by UUID.
func (r *Runner) GetRun(runUUID string) (*core.ModuleRun, error) {
	rows, err := r.db.Query(
		`SELECT uuid, module_id, module_version, session_uuid, inputs, status,
		 started_at, completed_at, outputs, error_detail, workspace_uuid, created_by
		 FROM module_runs WHERE uuid = ? AND workspace_uuid = ?`,
		runUUID, r.workspace,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	runs, err := scanRuns(rows)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("run not found: %s", runUUID)
	}
	return &runs[0], nil
}

func (r *Runner) saveRun(run *core.ModuleRun) error {
	inputsJSON, _ := json.Marshal(run.Inputs)
	outputsJSON, _ := json.Marshal(run.Outputs)
	snapshotJSON, _ := json.Marshal(run.SessionSnapshot)

	_, err := r.db.Exec(
		`INSERT INTO module_runs (uuid, module_id, module_version, session_uuid, session_snapshot, inputs, status,
		 started_at, completed_at, outputs, error_detail, workspace_uuid, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.UUID, run.ModuleID, run.ModuleVersion, run.SessionUUID,
		string(snapshotJSON), string(inputsJSON), string(run.Status),
		run.StartedAt.Format(time.RFC3339), nil,
		string(outputsJSON), nil,
		run.WorkspaceUUID, run.CreatedBy,
	)
	return err
}

func (r *Runner) updateRun(run *core.ModuleRun) {
	outputsJSON, _ := json.Marshal(run.Outputs)
	artifactJSON, _ := json.Marshal(run.ArtifactUUIDs)

	var completedStr *string
	if run.CompletedAt != nil {
		s := run.CompletedAt.Format(time.RFC3339)
		completedStr = &s
	}

	r.db.Exec(
		`UPDATE module_runs SET status = ?, completed_at = ?, outputs = ?, error_detail = ?, artifact_uuids = ?
		 WHERE uuid = ?`,
		string(run.Status), completedStr, string(outputsJSON), run.ErrorDetail, string(artifactJSON), run.UUID,
	)
}

func scanRuns(rows *sql.Rows) ([]core.ModuleRun, error) {
	var runs []core.ModuleRun
	for rows.Next() {
		var run core.ModuleRun
		var inputsJSON, outputsJSON, startedAt string
		var completedAt, errorDetail sql.NullString

		err := rows.Scan(
			&run.UUID, &run.ModuleID, &run.ModuleVersion, &run.SessionUUID,
			&inputsJSON, &run.Status, &startedAt, &completedAt,
			&outputsJSON, &errorDetail, &run.WorkspaceUUID, &run.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning run: %w", err)
		}

		run.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			run.CompletedAt = &t
		}
		if errorDetail.Valid {
			run.ErrorDetail = &errorDetail.String
		}
		json.Unmarshal([]byte(inputsJSON), &run.Inputs)
		json.Unmarshal([]byte(outputsJSON), &run.Outputs)

		runs = append(runs, run)
	}
	return runs, nil
}

type moduleExecContext struct {
	sdk.RunContext
	factory *stratusaws.ClientFactory
	creds   stratusaws.SessionCredentials
	graph   *graph.Store
}

type progressReporter struct {
	logger zerolog.Logger
	runID  string
}

func (p *progressReporter) Update(current int, message string) {
	p.logger.Debug().Str("run", p.runID).Int("progress", current).Str("msg", message).Msg("module progress")
}

func (p *progressReporter) Total(total int) {
	p.logger.Debug().Str("run", p.runID).Int("total", total).Msg("module total")
}

// RegisterBuiltinModules registers all built-in modules with the registry.
func RegisterBuiltinModules(reg *Registry, factory *stratusaws.ClientFactory, gs *graph.Store) {
	// IAM modules
	reg.Register(&EnumerateRolesModule{factory: factory, graph: gs})
	reg.Register(&EnumerateUsersModule{factory: factory})
	reg.Register(&CreateAccessKeyModule{factory: factory})
	reg.Register(&IAMPolicyAnalyzerModule{factory: factory})
	reg.Register(&IAMBackdoorRoleModule{factory: factory})

	// STS modules
	reg.Register(&STSEnumerateRolesChainModule{factory: factory, graph: gs})

	// S3 modules
	reg.Register(&FindPublicBucketsModule{factory: factory})
	reg.Register(&S3ExfilCheckModule{factory: factory})

	// EC2 modules
	reg.Register(&EnumerateEC2Module{factory: factory})
	reg.Register(&SecurityGroupAuditModule{factory: factory})
	reg.Register(&ModifySecurityGroupModule{factory: factory})
	reg.Register(&EC2UserDataExtractModule{factory: factory})
	reg.Register(&EBSEnumerateSnapshotsModule{factory: factory})

	// Lambda modules
	reg.Register(&EnumerateLambdaModule{factory: factory})
	reg.Register(&LambdaEnvVarsModule{factory: factory})

	// CloudTrail modules
	reg.Register(&CloudTrailStatusModule{factory: factory})
	reg.Register(&StopTrailModule{factory: factory})

	// CloudWatch modules
	reg.Register(&CloudWatchEnumerateLogsModule{factory: factory})

	// KMS modules
	reg.Register(&KMSKeyInventoryModule{factory: factory})

	// Secrets Manager modules
	reg.Register(&SecretsManagerEnumerateModule{factory: factory})

	// SSM modules
	reg.Register(&SSMEnumerateParametersModule{factory: factory})

	// RDS modules
	reg.Register(&RDSEnumerateModule{factory: factory})

	// DynamoDB modules
	reg.Register(&DynamoDBEnumerateModule{factory: factory})

	// ECS modules
	reg.Register(&ECSEnumerateModule{factory: factory})

	// SNS modules
	reg.Register(&SNSEnumerateModule{factory: factory})

	// MWAA modules
	reg.Register(&MWAAEnumerateModule{factory: factory, graph: gs})

	// SageMaker modules
	reg.Register(&SageMakerEnumerateModule{factory: factory})
	reg.Register(&SageMakerPrivescCheckModule{factory: factory})

	// AWS Config modules
	reg.Register(&ConfigEnumerateModule{factory: factory})

	// CodeBuild modules
	reg.Register(&CodeBuildEnumerateModule{factory: factory})
	reg.Register(&CodeBuildPrivescCheckModule{factory: factory})

	// Cognito modules
	reg.Register(&CognitoEnumerateModule{factory: factory})
	reg.Register(&CognitoPrivescCheckModule{factory: factory})

	// EKS modules
	reg.Register(&EKSEnumerateModule{factory: factory, graph: gs})
	reg.Register(&EKSPrivescCheckModule{factory: factory})

	// Analysis modules
	reg.Register(&AttackPathAnalyzerModule{db: reg.db, graph: gs})
}
