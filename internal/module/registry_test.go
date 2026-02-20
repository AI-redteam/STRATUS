package module

import (
	"testing"

	"github.com/rs/zerolog"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

type mockModule struct {
	meta sdk.ModuleMeta
}

func (m *mockModule) Meta() sdk.ModuleMeta                                      { return m.meta }
func (m *mockModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult           { return sdk.PreflightResult{} }
func (m *mockModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult                 { return sdk.DryRunResult{} }
func (m *mockModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult    { return sdk.RunResult{} }
func (m *mockModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return sdk.RunResult{}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	logger := zerolog.Nop()
	reg := NewRegistry(nil, logger)

	mod := &mockModule{
		meta: sdk.ModuleMeta{
			ID:       "com.test.module",
			Name:     "Test Module",
			Version:  "1.0.0",
			Services: []string{"iam"},
			RiskClass: sdk.RiskReadOnly,
		},
	}

	reg.Register(mod)

	got, ok := reg.Get("com.test.module")
	if !ok {
		t.Fatal("expected module to be found")
	}
	if got.Meta().ID != "com.test.module" {
		t.Errorf("unexpected module ID: %s", got.Meta().ID)
	}

	_, ok = reg.Get("nonexistent")
	if ok {
		t.Error("expected module to not be found")
	}
}

func TestRegistryList(t *testing.T) {
	logger := zerolog.Nop()
	reg := NewRegistry(nil, logger)

	reg.Register(&mockModule{meta: sdk.ModuleMeta{ID: "a", Name: "A"}})
	reg.Register(&mockModule{meta: sdk.ModuleMeta{ID: "b", Name: "B"}})
	reg.Register(&mockModule{meta: sdk.ModuleMeta{ID: "c", Name: "C"}})

	metas := reg.List()
	if len(metas) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(metas))
	}
}

func TestRegistrySearch(t *testing.T) {
	logger := zerolog.Nop()
	reg := NewRegistry(nil, logger)

	reg.Register(&mockModule{meta: sdk.ModuleMeta{
		ID: "com.stratus.iam.enumerate-roles", Name: "Enumerate IAM Roles",
		Services: []string{"iam"}, RiskClass: sdk.RiskReadOnly,
	}})
	reg.Register(&mockModule{meta: sdk.ModuleMeta{
		ID: "com.stratus.s3.find-public", Name: "Find Public S3",
		Services: []string{"s3"}, RiskClass: sdk.RiskReadOnly,
	}})
	reg.Register(&mockModule{meta: sdk.ModuleMeta{
		ID: "com.stratus.iam.privesc", Name: "Privilege Escalation Test",
		Services: []string{"iam"}, RiskClass: sdk.RiskWrite,
	}})

	// Search by keyword
	results := reg.Search("enumerate", "", "", "")
	if len(results) != 1 {
		t.Errorf("keyword search: expected 1 result, got %d", len(results))
	}

	// Search by service
	results = reg.Search("", "iam", "", "")
	if len(results) != 2 {
		t.Errorf("service search: expected 2 results, got %d", len(results))
	}

	// Search by risk class
	results = reg.Search("", "", "write", "")
	if len(results) != 1 {
		t.Errorf("risk search: expected 1 result, got %d", len(results))
	}

	// Combined filters
	results = reg.Search("", "iam", "read_only", "")
	if len(results) != 1 {
		t.Errorf("combined search: expected 1 result, got %d", len(results))
	}
}

func TestBuiltinModulesRegister(t *testing.T) {
	logger := zerolog.Nop()
	reg := NewRegistry(nil, logger)

	RegisterBuiltinModules(reg, nil, nil)

	// Verify all expected modules are present
	expectedIDs := map[string]bool{
		"com.stratus.iam.enumerate-roles":            false,
		"com.stratus.iam.enumerate-users":            false,
		"com.stratus.iam.create-access-key":          false,
		"com.stratus.iam.policy-analyzer":            false,
		"com.stratus.iam.backdoor-role":              false,
		"com.stratus.sts.enumerate-roles-chain":      false,
		"com.stratus.s3.find-public-buckets":         false,
		"com.stratus.s3.exfil-check":                 false,
		"com.stratus.ec2.enumerate-instances":        false,
		"com.stratus.ec2.security-group-audit":       false,
		"com.stratus.ec2.modify-security-group":      false,
		"com.stratus.ec2.userdata-extract":           false,
		"com.stratus.ebs.enumerate-snapshots":        false,
		"com.stratus.lambda.enumerate-functions":     false,
		"com.stratus.lambda.extract-env-vars":        false,
		"com.stratus.cloudtrail.status":              false,
		"com.stratus.cloudtrail.stop-trail":          false,
		"com.stratus.cloudwatch.enumerate-logs":      false,
		"com.stratus.kms.key-inventory":              false,
		"com.stratus.secretsmanager.enumerate":       false,
		"com.stratus.ssm.enumerate-parameters":       false,
		"com.stratus.rds.enumerate-instances":        false,
		"com.stratus.dynamodb.enumerate-tables":      false,
		"com.stratus.ecs.enumerate-clusters":         false,
		"com.stratus.sns.enumerate-topics":           false,
		"com.stratus.mwaa.enumerate":                 false,
		"com.stratus.sagemaker.enumerate":            false,
		"com.stratus.sagemaker.privesc-check":        false,
		"com.stratus.config.enumerate":               false,
		"com.stratus.codebuild.enumerate":            false,
		"com.stratus.codebuild.privesc-check":        false,
		"com.stratus.cognito.enumerate":              false,
		"com.stratus.cognito.privesc-check":          false,
		"com.stratus.eks.enumerate":                  false,
		"com.stratus.eks.privesc-check":              false,
	}

	metas := reg.List()
	if len(metas) != len(expectedIDs) {
		t.Fatalf("expected %d built-in modules, got %d", len(expectedIDs), len(metas))
	}

	for _, meta := range metas {
		if _, ok := expectedIDs[meta.ID]; ok {
			expectedIDs[meta.ID] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected module not registered: %s", id)
		}
	}
}
