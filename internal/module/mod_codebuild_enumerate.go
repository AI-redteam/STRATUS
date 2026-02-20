package module

import (
	"context"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CodeBuildEnumerateModule lists CodeBuild projects, source credentials, and
// recent builds. Identifies sensitive environment variables, privileged build
// containers, webhook configurations, and service role targets.
type CodeBuildEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *CodeBuildEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.codebuild.enumerate",
		Name:        "Enumerate CodeBuild Projects",
		Version:     "1.0.0",
		Description: "Lists all CodeBuild projects with detailed configuration including service roles, source types, environment variables, webhook filters, and source credentials. Identifies projects with plaintext secrets in env vars, privileged Docker mode, weak webhook filters (PR-based triggers without actor restrictions), and S3-sourced buildspecs that could be backdoored. Extracts all service role ARNs for privilege escalation assessment.",
		Services:    []string{"codebuild"},
		RequiredActions: []string{
			"codebuild:ListProjects",
			"codebuild:BatchGetProjects",
			"codebuild:ListSourceCredentials",
			"codebuild:ListBuildsForProject",
			"codebuild:BatchGetBuilds",
		},
		RequiredResources: []string{"arn:aws:codebuild:*:*:project/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "include_builds", Type: "bool", Default: true, Description: "Also enumerate recent builds per project"},
			{Name: "max_builds_per_project", Type: "int", Default: 5, Description: "Maximum recent builds to fetch per project"},
			{Name: "max_projects", Type: "int", Default: 100, Description: "Maximum projects to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "project_count", Type: "int", Description: "Total projects found"},
			{Name: "projects", Type: "[]map", Description: "Project details"},
			{Name: "source_credentials", Type: "[]map", Description: "Configured source credentials (ARN/type only)"},
			{Name: "service_roles", Type: "[]string", Description: "Unique service role ARNs"},
			{Name: "findings", Type: "[]map", Description: "Security findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1588.004/",
			"https://attack.mitre.org/techniques/T1078.004/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "CodeBuild", SortOrder: 1},
	}
}

func (m *CodeBuildEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"codebuild:ListProjects", "codebuild:BatchGetProjects", "codebuild:ListSourceCredentials"}
	if ctx.InputBool("include_builds") {
		calls = append(calls, "codebuild:ListBuildsForProject", "codebuild:BatchGetBuilds")
	}
	return sdk.PreflightResult{PlannedAPICalls: calls, Confidence: 1.0}
}

func (m *CodeBuildEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would enumerate all CodeBuild projects and source credentials."
	if ctx.InputBool("include_builds") {
		desc += " Would also list recent builds per project."
	}
	return sdk.DryRunResult{Description: desc, WouldMutate: false}
}

func (m *CodeBuildEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxProjects := ctx.InputInt("max_projects")
	if maxProjects <= 0 {
		maxProjects = 100
	}
	includeBuilds := ctx.InputBool("include_builds")
	maxBuilds := ctx.InputInt("max_builds_per_project")
	if maxBuilds <= 0 {
		maxBuilds = 5
	}

	var findings []map[string]any
	roleSet := make(map[string]bool)

	prog.Total(3)

	// --- Step 1: List and describe projects ---
	prog.Update(1, "Listing CodeBuild projects")

	projectNames, err := m.factory.ListCodeBuildProjects(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing CodeBuild projects: %w", err))
	}

	if len(projectNames) > maxProjects {
		projectNames = projectNames[:maxProjects]
	}

	var projectResults []map[string]any

	if len(projectNames) > 0 {
		projects, err := m.factory.BatchGetCodeBuildProjects(bgCtx, creds, projectNames)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "projects", "finding": "BatchGetFailed", "severity": "info",
				"detail": fmt.Sprintf("could not get project details: %v", err),
			})
		} else {
			for _, p := range projects {
				if p.ServiceRoleARN != "" {
					roleSet[p.ServiceRoleARN] = true
				}

				entry := map[string]any{
					"name":             p.Name,
					"arn":              p.ARN,
					"service_role_arn": p.ServiceRoleARN,
					"source_type":     p.SourceType,
					"source_location": p.SourceLocation,
					"buildspec":       p.BuildspecFile,
					"environment":     p.Environment,
					"encryption_key":  p.EncryptionKey,
					"created":         p.Created,
					"last_modified":   p.LastModified,
				}

				if p.Webhook != nil {
					entry["webhook"] = p.Webhook
				}

				// Analyze environment variables
				var sensitiveVars []map[string]any
				for _, ev := range p.EnvVars {
					if ev.Type == "PLAINTEXT" {
						lower := strings.ToLower(ev.Name)
						if strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
							strings.Contains(lower, "token") || strings.Contains(lower, "key") ||
							strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") {
							sensitiveVars = append(sensitiveVars, map[string]any{
								"name": ev.Name,
								"type": ev.Type,
							})
						}
					}
				}
				if len(sensitiveVars) > 0 {
					entry["sensitive_env_vars"] = sensitiveVars
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("project/%s", p.Name),
						"finding":  "PlaintextSecrets",
						"severity": "high",
						"detail":   fmt.Sprintf("Project %s has %d environment variables with sensitive names stored as PLAINTEXT (not Secrets Manager/Parameter Store).", p.Name, len(sensitiveVars)),
					})
				}

				// Flag privileged Docker mode
				if p.Environment.PrivilegedMode {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("project/%s", p.Name),
						"finding":  "PrivilegedDocker",
						"severity": "medium",
						"detail":   fmt.Sprintf("Project %s runs in privileged Docker mode. Build containers can access Docker socket and escape container isolation.", p.Name),
					})
				}

				// Check for S3-sourced buildspec (backdoor target)
				if p.SourceType == "S3" && p.SourceLocation != "" {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("project/%s", p.Name),
						"finding":  "S3SourceBuildspec",
						"severity": "medium",
						"detail":   fmt.Sprintf("Project %s uses S3 source (%s). If S3 write access is available, the buildspec can be backdoored to steal service role credentials.", p.Name, p.SourceLocation),
					})
				}

				// Check webhook for weak PR filters
				if p.Webhook != nil && len(p.Webhook.FilterGroups) > 0 {
					hasActorFilter := false
					hasPREvent := false
					for _, fg := range p.Webhook.FilterGroups {
						for _, filter := range fg {
							parts := strings.SplitN(filter, ":", 3)
							if len(parts) >= 2 {
								if parts[0] == "ACTOR_ACCOUNT_ID" {
									hasActorFilter = true
								}
								if parts[0] == "EVENT" && (strings.Contains(parts[1], "PULL_REQUEST") || strings.Contains(parts[1], "WORKFLOW_JOB")) {
									hasPREvent = true
								}
							}
						}
					}
					if hasPREvent && !hasActorFilter {
						findings = append(findings, map[string]any{
							"resource": fmt.Sprintf("project/%s", p.Name),
							"finding":  "WeakWebhookFilter",
							"severity": "high",
							"detail":   fmt.Sprintf("Project %s has PR-triggered webhook without ACTOR_ACCOUNT_ID filter. External PRs could trigger builds and execute arbitrary code (CodeBreach-style attack).", p.Name),
						})
					}
				}

				// Fetch recent builds if requested
				if includeBuilds {
					buildIDs, err := m.factory.ListCodeBuildBuilds(bgCtx, creds, p.Name)
					if err == nil && len(buildIDs) > 0 {
						if len(buildIDs) > maxBuilds {
							buildIDs = buildIDs[:maxBuilds]
						}
						builds, err := m.factory.BatchGetCodeBuildBuilds(bgCtx, creds, buildIDs)
						if err == nil {
							var buildSummaries []map[string]any
							for _, b := range builds {
								buildSummaries = append(buildSummaries, map[string]any{
									"id":              b.ID,
									"status":          b.BuildStatus,
									"source_version":  b.SourceVersion,
									"initiator":       b.Initiator,
									"start_time":      b.StartTime,
								})
							}
							entry["recent_builds"] = buildSummaries
						}
					}
				}

				projectResults = append(projectResults, entry)
			}
		}
	}

	// --- Step 2: Source credentials ---
	prog.Update(2, "Listing source credentials")

	var sourceCredResults []map[string]any
	sourceCreds, err := m.factory.ListCodeBuildSourceCredentials(bgCtx, creds)
	if err == nil {
		for _, sc := range sourceCreds {
			sourceCredResults = append(sourceCredResults, map[string]any{
				"arn":         sc.ARN,
				"server_type": sc.ServerType,
				"auth_type":   sc.AuthType,
			})
		}
		if len(sourceCreds) > 0 {
			findings = append(findings, map[string]any{
				"resource": "source_credentials",
				"finding":  "ExternalRepoCredentials",
				"severity": "info",
				"detail":   fmt.Sprintf("Found %d external repository credentials (GitHub/GitLab/Bitbucket tokens). These are stored in Secrets Manager and could be retrieved with appropriate permissions.", len(sourceCreds)),
			})
		}
	}

	prog.Update(3, "Analysis complete")

	var roles []string
	for r := range roleSet {
		roles = append(roles, r)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"project_count":      len(projectResults),
			"projects":           projectResults,
			"source_credentials": sourceCredResults,
			"service_roles":      roles,
			"findings":           findings,
		},
	}
}

func (m *CodeBuildEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
