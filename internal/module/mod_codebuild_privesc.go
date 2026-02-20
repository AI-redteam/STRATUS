package module

import (
	"context"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CodeBuildPrivescCheckModule identifies CodeBuild privilege escalation paths
// based on techniques documented in hacktricks-cloud. Checks for buildspec
// override targets, role swapping via UpdateProject, S3 buildspec backdoor
// paths, and weak webhook configurations.
type CodeBuildPrivescCheckModule struct {
	factory *aws.ClientFactory
}

func (m *CodeBuildPrivescCheckModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.codebuild.privesc-check",
		Name:        "CodeBuild Privilege Escalation Check",
		Version:     "1.0.0",
		Description: "Identifies CodeBuild privilege escalation paths by analyzing projects, service roles, and build configurations. Checks for: buildspec override via StartBuild (role credential theft), project creation/modification with iam:PassRole (arbitrary role attachment), S3-sourced buildspec backdoor paths, privileged Docker containers, and weak webhook filters enabling external code execution. Maps each finding to specific exploitation techniques.",
		Services:    []string{"codebuild"},
		RequiredActions: []string{
			"codebuild:ListProjects",
			"codebuild:BatchGetProjects",
		},
		RequiredResources: []string{"arn:aws:codebuild:*:*:project/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_projects", Type: "int", Default: 100, Description: "Maximum projects to analyze"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "privesc_paths", Type: "[]map", Description: "Identified privilege escalation paths"},
			{Name: "path_count", Type: "int", Description: "Total escalation paths found"},
			{Name: "target_roles", Type: "[]map", Description: "Service roles that can be targeted"},
			{Name: "summary", Type: "map", Description: "Aggregate summary"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1059/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "CodeBuild", SortOrder: 2},
	}
}

func (m *CodeBuildPrivescCheckModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"codebuild:ListProjects", "codebuild:BatchGetProjects"},
		Confidence:      1.0,
	}
}

func (m *CodeBuildPrivescCheckModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate CodeBuild projects and analyze service roles, source configurations, and webhook filters for privilege escalation paths.",
		WouldMutate: false,
	}
}

func (m *CodeBuildPrivescCheckModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxProjects := ctx.InputInt("max_projects")
	if maxProjects <= 0 {
		maxProjects = 100
	}

	prog.Total(3)

	// --- Step 1: Get all projects ---
	prog.Update(1, "Listing CodeBuild projects")

	projectNames, err := m.factory.ListCodeBuildProjects(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing CodeBuild projects: %w", err))
	}
	if len(projectNames) > maxProjects {
		projectNames = projectNames[:maxProjects]
	}
	if len(projectNames) == 0 {
		return sdk.RunResult{
			Outputs: map[string]any{
				"privesc_paths": []map[string]any{},
				"path_count":    0,
				"target_roles":  []map[string]any{},
				"summary":       map[string]any{"total_paths": 0, "total_projects": 0},
			},
		}
	}

	prog.Update(2, "Analyzing project configurations")

	projects, err := m.factory.BatchGetCodeBuildProjects(bgCtx, creds, projectNames)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("getting CodeBuild project details: %w", err))
	}

	var privescPaths []map[string]any
	var targetRoles []map[string]any
	roleSet := make(map[string]bool)

	for _, p := range projects {
		if p.ServiceRoleARN != "" && !roleSet[p.ServiceRoleARN] {
			roleSet[p.ServiceRoleARN] = true

			roleName := p.ServiceRoleARN
			if idx := strings.LastIndex(p.ServiceRoleARN, "/"); idx >= 0 {
				roleName = p.ServiceRoleARN[idx+1:]
			}

			targetRoles = append(targetRoles, map[string]any{
				"role_arn":    p.ServiceRoleARN,
				"role_name":  roleName,
				"project":    p.Name,
				"privileged": p.Environment.PrivilegedMode,
			})
		}

		// Technique 1: StartBuild buildspec override — steal existing service role
		privescPaths = append(privescPaths, map[string]any{
			"finding":          "BuildspecOverride",
			"severity":         "high",
			"principal_type":   "codebuild_project",
			"principal_name":   p.Name,
			"principal_arn":    p.ARN,
			"target_role":     p.ServiceRoleARN,
			"description":     fmt.Sprintf("StartBuild on project %s with --buildspec-override executes arbitrary commands under service role. Credentials available at http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.", p.Name),
			"required_actions": []string{"codebuild:StartBuild"},
			"reference":        "T1059",
		})

		// Technique 2: UpdateProject buildspec — modify without changing role
		privescPaths = append(privescPaths, map[string]any{
			"finding":          "UpdateProjectBuildspec",
			"severity":         "high",
			"principal_type":   "codebuild_project",
			"principal_name":   p.Name,
			"principal_arn":    p.ARN,
			"target_role":     p.ServiceRoleARN,
			"description":     fmt.Sprintf("UpdateProject on %s can replace the buildspec and environment image to inject commands. No iam:PassRole needed since the existing role is reused.", p.Name),
			"required_actions": []string{"codebuild:UpdateProject", "codebuild:StartBuild"},
			"reference":        "T1059",
		})

		// Technique 3: UpdateProject with iam:PassRole — swap to any role
		privescPaths = append(privescPaths, map[string]any{
			"finding":          "UpdateProjectRoleSwap",
			"severity":         "critical",
			"principal_type":   "codebuild_project",
			"principal_name":   p.Name,
			"principal_arn":    p.ARN,
			"target_role":     p.ServiceRoleARN,
			"description":     fmt.Sprintf("UpdateProject on %s with iam:PassRole can change the service role to any CodeBuild-compatible role. Combined with StartBuild for arbitrary role credential theft.", p.Name),
			"required_actions": []string{"codebuild:UpdateProject", "iam:PassRole", "codebuild:StartBuild"},
			"reference":        "T1078.004",
		})

		// Technique 4: S3 buildspec backdoor
		if p.SourceType == "S3" && p.SourceLocation != "" {
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "S3BuildspecBackdoor",
				"severity":         "high",
				"principal_type":   "codebuild_project",
				"principal_name":   p.Name,
				"principal_arn":    p.ARN,
				"target_role":     p.ServiceRoleARN,
				"s3_location":     p.SourceLocation,
				"description":     fmt.Sprintf("Project %s fetches buildspec from S3 (%s). With s3:PutObject on this bucket, the buildspec can be backdoored to steal credentials on next build.", p.Name, p.SourceLocation),
				"required_actions": []string{"s3:GetObject", "s3:PutObject", "codebuild:StartBuild"},
				"reference":        "T1059",
			})
		}

		// Technique 5: Weak webhook — external code execution
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
						if parts[0] == "EVENT" && strings.Contains(parts[1], "PULL_REQUEST") {
							hasPREvent = true
						}
					}
				}
			}
			if hasPREvent && !hasActorFilter {
				privescPaths = append(privescPaths, map[string]any{
					"finding":          "WebhookPRExploit",
					"severity":         "critical",
					"principal_type":   "codebuild_project",
					"principal_name":   p.Name,
					"principal_arn":    p.ARN,
					"target_role":     p.ServiceRoleARN,
					"description":     fmt.Sprintf("Project %s has a PR-triggered webhook without ACTOR_ACCOUNT_ID restriction. An external attacker can open a PR with malicious buildspec to execute arbitrary code under the service role (CodeBreach-style).", p.Name),
					"required_actions": []string{"(external: repository write access)"},
					"reference":        "T1059",
				})
			}
		}

		// Technique 6: Privileged Docker container escape
		if p.Environment.PrivilegedMode {
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "PrivilegedDockerEscape",
				"severity":         "high",
				"principal_type":   "codebuild_project",
				"principal_name":   p.Name,
				"principal_arn":    p.ARN,
				"target_role":     p.ServiceRoleARN,
				"description":     fmt.Sprintf("Project %s runs with privileged Docker mode. Build containers can mount the host filesystem and potentially access other containers' credentials or escape to the underlying EC2 instance.", p.Name),
				"required_actions": []string{"codebuild:StartBuild"},
				"reference":        "T1059",
			})
		}
	}

	// Technique 7: CreateProject + iam:PassRole — arbitrary role execution
	privescPaths = append(privescPaths, map[string]any{
		"finding":          "CreateProjectWithRole",
		"severity":         "critical",
		"principal_type":   "codebuild_service",
		"principal_name":   "CodeBuild",
		"principal_arn":    "",
		"target_role":     "",
		"description":     "codebuild:CreateProject with iam:PassRole allows creating a new project with any CodeBuild-compatible IAM role. Combined with StartBuild for complete role credential theft.",
		"required_actions": []string{
			"codebuild:CreateProject",
			"iam:PassRole",
			"codebuild:StartBuild",
		},
		"reference": "T1078.004",
	})

	// --- Step 3: Summary ---
	prog.Update(3, "Building summary")

	findingCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	for _, p := range privescPaths {
		if t, ok := p["finding"].(string); ok {
			findingCounts[t]++
		}
		if s, ok := p["severity"].(string); ok {
			severityCounts[s]++
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"privesc_paths": privescPaths,
			"path_count":    len(privescPaths),
			"target_roles":  targetRoles,
			"summary": map[string]any{
				"total_paths":      len(privescPaths),
				"total_projects":   len(projects),
				"unique_roles":     len(roleSet),
				"finding_counts":   findingCounts,
				"severity_counts":  severityCounts,
			},
		},
	}
}

func (m *CodeBuildPrivescCheckModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
