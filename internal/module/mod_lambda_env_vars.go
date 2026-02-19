package module

import (
	"context"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// LambdaEnvVarsModule extracts environment variables from Lambda functions,
// which frequently contain API keys, database credentials, and secrets.
type LambdaEnvVarsModule struct {
	factory *aws.ClientFactory
}

func (m *LambdaEnvVarsModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.lambda.extract-env-vars",
		Name:        "Extract Lambda Environment Variables",
		Version:     "1.0.0",
		Description: "Retrieves environment variables from Lambda functions. Lambda environment variables frequently contain database credentials, API keys, third-party service tokens, and other secrets that developers store for convenience. Identifies variables with sensitive-looking names or values.",
		Services:    []string{"lambda"},
		RequiredActions: []string{
			"lambda:ListFunctions",
			"lambda:GetFunctionConfiguration",
		},
		RequiredResources: []string{"arn:aws:lambda:*:*:function:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "function_name", Type: "string", Description: "Specific function name (leave empty for all)"},
			{Name: "max_functions", Type: "int", Default: 200, Description: "Maximum functions to check"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "functions_checked", Type: "int", Description: "Total functions checked"},
			{Name: "functions_with_env", Type: "int", Description: "Functions with environment variables"},
			{Name: "results", Type: "[]map", Description: "Per-function environment variable results"},
			{Name: "sensitive_findings", Type: "[]map", Description: "Variables with sensitive-looking names/values"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1552/005/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Lambda", SortOrder: 2},
	}
}

func (m *LambdaEnvVarsModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"lambda:ListFunctions (paginated)",
			"lambda:GetFunctionConfiguration (per function)",
		},
		Confidence: 1.0,
	}
}

func (m *LambdaEnvVarsModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	fnName := ctx.InputString("function_name")
	if fnName != "" {
		return sdk.DryRunResult{
			Description: fmt.Sprintf("Would call lambda:GetFunctionConfiguration on %q to retrieve environment variables.", fnName),
			WouldMutate: false,
			APICalls:    []string{"lambda:GetFunctionConfiguration"},
		}
	}
	return sdk.DryRunResult{
		Description: "Would list all Lambda functions and retrieve environment variables from each.",
		WouldMutate: false,
		APICalls:    []string{"lambda:ListFunctions", "lambda:GetFunctionConfiguration"},
	}
}

func (m *LambdaEnvVarsModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	fnName := ctx.InputString("function_name")
	maxFunctions := ctx.InputInt("max_functions")
	if maxFunctions <= 0 {
		maxFunctions = 200
	}

	var functionNames []string
	if fnName != "" {
		functionNames = []string{fnName}
	} else {
		fns, err := m.factory.ListLambdaFunctions(bgCtx, creds)
		if err != nil {
			return sdk.ErrResult(fmt.Errorf("listing Lambda functions: %w", err))
		}
		for _, fn := range fns {
			functionNames = append(functionNames, fn.FunctionName)
		}
		if len(functionNames) > maxFunctions {
			functionNames = functionNames[:maxFunctions]
		}
	}

	prog.Total(len(functionNames))

	var results []map[string]any
	var sensitiveFindings []map[string]any
	withEnv := 0

	for i, name := range functionNames {
		prog.Update(i+1, "Checking: "+name)

		envVars, err := m.factory.GetLambdaFunctionEnvVars(bgCtx, creds, name)
		if err != nil {
			results = append(results, map[string]any{
				"function_name": name,
				"error":         err.Error(),
			})
			continue
		}

		if len(envVars) == 0 {
			results = append(results, map[string]any{
				"function_name": name,
				"env_var_count": 0,
			})
			continue
		}

		withEnv++
		entry := map[string]any{
			"function_name": name,
			"env_var_count": len(envVars),
			"variables":     envVars,
		}

		// Scan for sensitive variables
		for key, value := range envVars {
			if isSensitiveEnvVar(key, value) {
				finding := map[string]any{
					"function":     name,
					"variable":     key,
					"value_preview": truncateSecret(value, 50),
					"reason":       classifySensitiveEnvVar(key, value),
				}
				sensitiveFindings = append(sensitiveFindings, finding)
			}
		}

		results = append(results, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"functions_checked":  len(functionNames),
			"functions_with_env": withEnv,
			"results":            results,
			"sensitive_findings": sensitiveFindings,
		},
	}
}

func (m *LambdaEnvVarsModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// sensitiveEnvVarPatterns contains patterns that indicate a variable may hold secrets.
var sensitiveEnvVarPatterns = []string{
	"password", "passwd", "secret", "api_key", "apikey", "token",
	"access_key", "private_key", "credential", "auth", "db_pass",
	"database_url", "connection_string", "jwt", "encryption_key",
	"master_key", "signing_key",
}

// isSensitiveEnvVar checks if an environment variable name or value looks sensitive.
func isSensitiveEnvVar(key, value string) bool {
	lowerKey := strings.ToLower(key)
	for _, pattern := range sensitiveEnvVarPatterns {
		if strings.Contains(lowerKey, pattern) {
			return true
		}
	}

	// Check value patterns
	if strings.HasPrefix(value, "AKIA") {
		return true
	}
	if strings.HasPrefix(value, "-----BEGIN") {
		return true
	}

	return false
}

// classifySensitiveEnvVar returns a reason why a variable looks sensitive.
func classifySensitiveEnvVar(key, value string) string {
	lowerKey := strings.ToLower(key)

	if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "passwd") {
		return "password_in_name"
	}
	if strings.Contains(lowerKey, "secret") {
		return "secret_in_name"
	}
	if strings.Contains(lowerKey, "api_key") || strings.Contains(lowerKey, "apikey") {
		return "api_key_in_name"
	}
	if strings.Contains(lowerKey, "token") {
		return "token_in_name"
	}
	if strings.Contains(lowerKey, "access_key") {
		return "access_key_in_name"
	}
	if strings.HasPrefix(value, "AKIA") {
		return "aws_access_key_in_value"
	}
	if strings.HasPrefix(value, "-----BEGIN") {
		return "pem_key_in_value"
	}
	return "sensitive_pattern_match"
}
