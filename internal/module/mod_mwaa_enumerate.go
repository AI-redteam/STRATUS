package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// MWAAEnumerateModule lists MWAA environments and inspects their execution
// roles for the known SQS wildcard cross-account vulnerability.
type MWAAEnumerateModule struct {
	factory *aws.ClientFactory
	graph   *graph.Store
}

func (m *MWAAEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.mwaa.enumerate",
		Name:        "Enumerate MWAA Environments",
		Version:     "1.0.0",
		Description: "Lists all Managed Workflows for Apache Airflow environments. Extracts execution roles, DAG S3 locations, network configuration, and webserver access mode. Checks execution role policies for the known SQS wildcard cross-account vulnerability (airflow-celery-* pattern). Public webserver access and overprivileged execution roles are flagged as findings.",
		Services:    []string{"mwaa", "iam"},
		RequiredActions: []string{
			"airflow:ListEnvironments",
			"airflow:GetEnvironment",
			"iam:GetRole",
			"iam:ListAttachedRolePolicies",
			"iam:ListRolePolicies",
			"iam:GetRolePolicy",
			"iam:GetPolicyVersion",
			"iam:GetPolicy",
		},
		RequiredResources: []string{
			"arn:aws:airflow:*:*:environment/*",
			"arn:aws:iam::*:role/*",
		},
		RiskClass: sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "check_role_policies", Type: "bool", Default: true, Description: "Inspect execution role policies for SQS wildcard and overprivileged access"},
			{Name: "max_environments", Type: "int", Default: 50, Description: "Maximum environments to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "environment_count", Type: "int", Description: "Total MWAA environments found"},
			{Name: "environments", Type: "[]map", Description: "Environment details"},
			{Name: "findings", Type: "[]map", Description: "Security findings"},
			{Name: "finding_count", Type: "int", Description: "Total findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "MWAA", SortOrder: 1},
	}
}

func (m *MWAAEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"airflow:ListEnvironments", "airflow:GetEnvironment"}
	if ctx.InputBool("check_role_policies") {
		calls = append(calls, "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:GetPolicyVersion")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *MWAAEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would enumerate all MWAA environments in the target region."
	if ctx.InputBool("check_role_policies") {
		desc += " Would also inspect execution role policies for SQS wildcard vulnerabilities."
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls:    []string{"airflow:ListEnvironments", "airflow:GetEnvironment", "iam:GetRole", "iam:ListAttachedRolePolicies"},
	}
}

func (m *MWAAEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	envNames, err := m.factory.ListMWAAEnvironments(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing MWAA environments: %w", err))
	}

	maxEnvs := ctx.InputInt("max_environments")
	if maxEnvs <= 0 {
		maxEnvs = 50
	}
	if len(envNames) > maxEnvs {
		envNames = envNames[:maxEnvs]
	}

	checkPolicies := ctx.InputBool("check_role_policies")
	prog.Total(len(envNames))

	environments := make([]map[string]any, 0)
	findings := make([]map[string]any, 0)

	for i, name := range envNames {
		prog.Update(i+1, "Inspecting: "+name)

		env, err := m.factory.GetMWAAEnvironment(bgCtx, creds, name)
		if err != nil {
			findings = append(findings, map[string]any{
				"environment": name,
				"finding":     "AccessDenied",
				"severity":    "info",
				"detail":      fmt.Sprintf("could not describe environment: %v", err),
			})
			continue
		}

		entry := map[string]any{
			"name":               env.Name,
			"arn":                env.ARN,
			"status":             env.Status,
			"execution_role_arn": env.ExecutionRoleARN,
			"source_bucket_arn":  env.SourceBucketARN,
			"dag_s3_path":        env.DAGS3Path,
			"webserver_url":      env.WebserverURL,
			"airflow_version":    env.AirflowVersion,
			"environment_class":  env.EnvironmentClass,
			"webserver_access":   env.WebserverAccess,
			"kms_key":            env.KMSKey,
			"security_groups":    env.SecurityGroupIDs,
			"subnets":            env.SubnetIDs,
		}

		// Flag public webserver access
		if strings.EqualFold(env.WebserverAccess, "PUBLIC_ONLY") {
			findings = append(findings, map[string]any{
				"environment": name,
				"finding":     "PublicWebserver",
				"severity":    "high",
				"detail":      "MWAA webserver is publicly accessible. DAG authors can execute arbitrary code on Airflow workers.",
			})
		}

		// Flag missing KMS encryption
		if env.KMSKey == "" {
			findings = append(findings, map[string]any{
				"environment": name,
				"finding":     "NoCustomKMS",
				"severity":    "low",
				"detail":      "Environment uses AWS-managed encryption key instead of customer-managed KMS key.",
			})
		}

		// Check execution role policies for SQS wildcard and overprivileged access
		if checkPolicies && env.ExecutionRoleARN != "" {
			roleName := extractRoleName(env.ExecutionRoleARN)
			if roleName != "" {
				roleFindings := m.analyzeExecutionRole(bgCtx, creds, name, roleName, ctx.Session.UUID)
				findings = append(findings, roleFindings...)
			}
		}

		environments = append(environments, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"environment_count": len(environments),
			"environments":      environments,
			"findings":          findings,
			"finding_count":     len(findings),
		},
	}
}

func (m *MWAAEnumerateModule) analyzeExecutionRole(ctx context.Context, creds aws.SessionCredentials, envName, roleName, sessionUUID string) []map[string]any {
	var findings []map[string]any

	detail, err := m.factory.GetIAMRoleDetail(ctx, creds, roleName)
	if err != nil {
		findings = append(findings, map[string]any{
			"environment": envName,
			"finding":     "RoleAnalysisFailed",
			"severity":    "info",
			"detail":      fmt.Sprintf("could not analyze execution role %s: %v", roleName, err),
		})
		return findings
	}

	// Add graph nodes and edge if available
	if m.graph != nil {
		m.graph.AddNode("mwaa:"+envName, "mwaa_environment", envName, sessionUUID, nil)
		m.graph.AddNode(detail.ARN, "iam_role", roleName, sessionUUID, nil)
		m.graph.AddEdge(core.GraphEdge{
			SourceNodeID: "mwaa:" + envName, TargetNodeID: detail.ARN,
			EdgeType: core.EdgeCanAssume, DiscoveredBySessionUUID: sessionUUID,
			DiscoveredAt: time.Now().UTC(), Confidence: 0.95,
		})
	}

	// Collect all policy documents for the role
	var policyDocs []string

	// Inline policies
	for _, policyName := range detail.InlinePolicies {
		doc, err := m.factory.GetIAMRoleInlinePolicy(ctx, creds, roleName, policyName)
		if err == nil {
			policyDocs = append(policyDocs, doc)
		}
	}

	// Managed policies
	for _, policyARN := range detail.AttachedPolicies {
		versionID, _, err := m.factory.GetIAMPolicyDefaultVersion(ctx, creds, policyARN)
		if err != nil {
			continue
		}
		doc, err := m.factory.GetIAMPolicyVersion(ctx, creds, policyARN, versionID)
		if err == nil {
			policyDocs = append(policyDocs, doc)
		}
	}

	// Analyze all collected policy documents
	for _, doc := range policyDocs {
		decoded, err := url.QueryUnescape(doc)
		if err != nil {
			decoded = doc
		}

		var policy struct {
			Statement []struct {
				Effect   string      `json:"Effect"`
				Action   interface{} `json:"Action"`
				Resource interface{} `json:"Resource"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
			continue
		}

		for _, stmt := range policy.Statement {
			if !strings.EqualFold(stmt.Effect, "allow") {
				continue
			}

			actions := flattenStringOrSlice(stmt.Action)
			resources := flattenStringOrSlice(stmt.Resource)

			// Check for SQS wildcard cross-account vulnerability
			hasSQSAction := false
			for _, a := range actions {
				if strings.HasPrefix(strings.ToLower(a), "sqs:") || a == "*" {
					hasSQSAction = true
					break
				}
			}
			if hasSQSAction {
				for _, r := range resources {
					if strings.Contains(r, "airflow-celery-") && strings.Contains(r, ":*:") {
						findings = append(findings, map[string]any{
							"environment": envName,
							"finding":     "SQSWildcardCrossAccount",
							"severity":    "critical",
							"detail":      fmt.Sprintf("Execution role has SQS permissions on cross-account wildcard resource: %s. This is architecturally required by MWAA but allows cross-account queue interaction with any airflow-celery-* queue.", r),
							"resource":    r,
						})
						break
					}
				}
			}

			// Check for admin-level access
			for _, a := range actions {
				if a == "*" {
					for _, r := range resources {
						if r == "*" {
							findings = append(findings, map[string]any{
								"environment": envName,
								"finding":     "AdminExecutionRole",
								"severity":    "critical",
								"detail":      "Execution role has full administrator access (Action:*, Resource:*). Any DAG can perform any AWS action.",
							})
						}
					}
				}
			}
		}
	}

	return findings
}

func extractRoleName(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return ""
}

func flattenStringOrSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func (m *MWAAEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
