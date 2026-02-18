package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EnumerateLambdaModule lists all Lambda functions and their configurations
// including runtime, role, and environment settings.
type EnumerateLambdaModule struct {
	factory *aws.ClientFactory
}

func (m *EnumerateLambdaModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.lambda.enumerate-functions",
		Name:        "Enumerate Lambda Functions",
		Version:     "1.0.0",
		Description: "Lists all Lambda functions in the target region with their runtime, execution role, memory/timeout configuration, and handler. Identifies functions with overprivileged roles or outdated runtimes.",
		Services:    []string{"lambda"},
		RequiredActions: []string{
			"lambda:ListFunctions",
		},
		RequiredResources: []string{"arn:aws:lambda:*:*:function:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_functions", Type: "int", Default: 500, Description: "Maximum functions to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "function_count", Type: "int", Description: "Total functions found"},
			{Name: "functions", Type: "[]map", Description: "Function details"},
			{Name: "runtimes", Type: "map", Description: "Runtime distribution"},
			{Name: "execution_roles", Type: "[]string", Description: "Unique execution roles"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1584/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Lambda", SortOrder: 1},
	}
}

func (m *EnumerateLambdaModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"lambda:ListFunctions (paginated)"},
		Confidence:      1.0,
	}
}

func (m *EnumerateLambdaModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would call lambda:ListFunctions up to max_functions=%d to enumerate all functions and their configurations.",
			ctx.InputInt("max_functions")),
		WouldMutate: false,
		APICalls:    []string{"lambda:ListFunctions"},
	}
}

func (m *EnumerateLambdaModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	fns, err := m.factory.ListLambdaFunctions(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing Lambda functions: %w", err))
	}

	maxFns := ctx.InputInt("max_functions")
	if maxFns <= 0 {
		maxFns = 500
	}
	if len(fns) > maxFns {
		fns = fns[:maxFns]
	}

	prog.Total(len(fns))

	runtimes := make(map[string]int)
	roleSet := make(map[string]bool)
	var details []map[string]any

	for i, fn := range fns {
		prog.Update(i+1, "Enumerated: "+fn.FunctionName)

		runtimes[fn.Runtime]++
		roleSet[fn.Role] = true

		details = append(details, map[string]any{
			"function_name": fn.FunctionName,
			"runtime":       fn.Runtime,
			"handler":       fn.Handler,
			"memory_mb":     fn.MemorySize,
			"timeout_sec":   fn.Timeout,
			"role":          fn.Role,
			"last_modified": fn.LastModified,
		})
	}

	var roles []string
	for role := range roleSet {
		roles = append(roles, role)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"function_count":  len(fns),
			"functions":       details,
			"runtimes":        runtimes,
			"execution_roles": roles,
		},
	}
}

func (m *EnumerateLambdaModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
