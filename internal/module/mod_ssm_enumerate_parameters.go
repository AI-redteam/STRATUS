package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// SSMEnumerateParametersModule lists SSM Parameter Store entries and optionally
// retrieves their values. SecureString parameters may contain credentials.
type SSMEnumerateParametersModule struct {
	factory *aws.ClientFactory
}

func (m *SSMEnumerateParametersModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ssm.enumerate-parameters",
		Name:        "Enumerate SSM Parameters",
		Version:     "1.0.0",
		Description: "Lists all SSM Parameter Store parameters in the target region. Optionally retrieves and decrypts values, identifying SecureString parameters that may contain credentials or connection strings.",
		Services:    []string{"ssm"},
		RequiredActions: []string{
			"ssm:DescribeParameters",
			"ssm:GetParameter",
		},
		RequiredResources: []string{"arn:aws:ssm:*:*:parameter/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "retrieve_values", Type: "bool", Default: false, Description: "Retrieve parameter values (requires ssm:GetParameter)"},
			{Name: "decrypt", Type: "bool", Default: true, Description: "Decrypt SecureString parameters (requires kms:Decrypt)"},
			{Name: "max_parameters", Type: "int", Default: 500, Description: "Maximum number of parameters to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "parameter_count", Type: "int", Description: "Total parameters found"},
			{Name: "parameters", Type: "[]map", Description: "Parameter metadata and optionally values"},
			{Name: "secure_string_count", Type: "int", Description: "Count of SecureString parameters"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1552/005/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "SSM", SortOrder: 1},
	}
}

func (m *SSMEnumerateParametersModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"ssm:DescribeParameters (paginated)"}
	if ctx.InputBool("retrieve_values") {
		calls = append(calls, "ssm:GetParameter (per parameter)")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *SSMEnumerateParametersModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would call ssm:DescribeParameters to list all parameters."
	if ctx.InputBool("retrieve_values") {
		desc += " Would also call ssm:GetParameter for each parameter."
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls:    []string{"ssm:DescribeParameters", "ssm:GetParameter"},
	}
}

func (m *SSMEnumerateParametersModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	params, err := m.factory.ListSSMParameters(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing parameters: %w", err))
	}

	maxParams := ctx.InputInt("max_parameters")
	if maxParams <= 0 {
		maxParams = 500
	}
	if len(params) > maxParams {
		params = params[:maxParams]
	}

	retrieveValues := ctx.InputBool("retrieve_values")
	decrypt := ctx.InputBool("decrypt")
	prog.Total(len(params))

	var results []map[string]any
	secureStringCount := 0

	for i, param := range params {
		prog.Update(i+1, "Processing: "+param.Name)

		entry := map[string]any{
			"name":          param.Name,
			"type":          param.Type,
			"version":       param.Version,
			"last_modified": param.LastModified,
		}

		if param.Type == "SecureString" {
			secureStringCount++
		}

		if retrieveValues {
			value, paramType, err := m.factory.GetSSMParameterValue(bgCtx, creds, param.Name, decrypt)
			if err == nil {
				entry["value"] = truncateSecret(value, 200)
				entry["value_length"] = len(value)
				entry["resolved_type"] = paramType
			} else {
				entry["retrieval_error"] = err.Error()
			}
		}

		results = append(results, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"parameter_count":     len(results),
			"parameters":         results,
			"secure_string_count": secureStringCount,
		},
	}
}

func (m *SSMEnumerateParametersModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
