package module

import (
	"context"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// SageMakerPrivescCheckModule identifies SageMaker privilege escalation paths
// based on the techniques documented in hacktricks-cloud. It checks for
// presigned URL generation, notebook instance role theft, domain role swapping,
// lifecycle config injection, and processing/training job abuse.
type SageMakerPrivescCheckModule struct {
	factory *aws.ClientFactory
}

func (m *SageMakerPrivescCheckModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.sagemaker.privesc-check",
		Name:        "SageMaker Privilege Escalation Check",
		Version:     "1.0.0",
		Description: "Identifies SageMaker privilege escalation paths by analyzing notebook instances, Studio domains, and user profiles. Checks for: presigned URL targets (notebooks with high-privilege roles), internet-enabled notebooks for credential exfiltration, lifecycle config injection points for persistence, domain/profile execution role targets for role swapping, and training/processing job creation paths. Maps each finding to known privesc techniques.",
		Services:    []string{"sagemaker"},
		RequiredActions: []string{
			"sagemaker:ListNotebookInstances",
			"sagemaker:DescribeNotebookInstance",
			"sagemaker:ListDomains",
			"sagemaker:DescribeDomain",
			"sagemaker:ListUserProfiles",
			"sagemaker:DescribeUserProfile",
			"sagemaker:ListNotebookInstanceLifecycleConfigs",
			"sagemaker:ListStudioLifecycleConfigs",
		},
		RequiredResources: []string{"arn:aws:sagemaker:*:*:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_items", Type: "int", Default: 100, Description: "Maximum items per resource type to check"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "privesc_paths", Type: "[]map", Description: "Identified privilege escalation paths"},
			{Name: "path_count", Type: "int", Description: "Total escalation paths found"},
			{Name: "high_value_roles", Type: "[]map", Description: "High-value execution roles that could be targeted"},
			{Name: "persistence_vectors", Type: "[]map", Description: "Lifecycle configs usable for persistence"},
			{Name: "summary", Type: "map", Description: "Aggregate summary of findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1098/",
			"https://attack.mitre.org/techniques/T1059/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "SageMaker", SortOrder: 2},
	}
}

func (m *SageMakerPrivescCheckModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance",
			"sagemaker:ListDomains", "sagemaker:DescribeDomain",
			"sagemaker:ListUserProfiles", "sagemaker:DescribeUserProfile",
			"sagemaker:ListNotebookInstanceLifecycleConfigs",
			"sagemaker:ListStudioLifecycleConfigs",
		},
		Confidence: 1.0,
	}
}

func (m *SageMakerPrivescCheckModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate SageMaker notebooks, domains, and user profiles to identify privilege escalation paths including presigned URL targets, role swapping opportunities, and lifecycle config injection points.",
		WouldMutate: false,
		APICalls: []string{
			"sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance",
			"sagemaker:ListDomains", "sagemaker:DescribeDomain",
			"sagemaker:ListUserProfiles", "sagemaker:DescribeUserProfile",
		},
	}
}

func (m *SageMakerPrivescCheckModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxItems := ctx.InputInt("max_items")
	if maxItems <= 0 {
		maxItems = 100
	}

	var privescPaths []map[string]any
	var highValueRoles []map[string]any
	var persistenceVectors []map[string]any
	roleSet := make(map[string]bool)

	prog.Total(5)

	// --- Step 1: Notebook Instance Presigned URL Targets ---
	prog.Update(1, "Checking notebook instances for presigned URL targets")

	notebooks, err := m.factory.ListSageMakerNotebookInstances(bgCtx, creds)
	if err == nil {
		for i, nb := range notebooks {
			if i >= maxItems {
				break
			}
			detail, err := m.factory.DescribeSageMakerNotebookInstance(bgCtx, creds, nb.NotebookName)
			if err != nil {
				continue
			}

			if detail.RoleARN != "" {
				roleSet[detail.RoleARN] = true
			}

			// Running notebooks are presigned URL targets
			if detail.Status == "InService" && detail.RoleARN != "" {
				privescPaths = append(privescPaths, map[string]any{
					"technique":     "PresignedNotebookURL",
					"severity":      "high",
					"resource_name": detail.NotebookName,
					"resource_arn":  detail.NotebookARN,
					"target_role":   detail.RoleARN,
					"description":   "Running notebook instance can be accessed via CreatePresignedNotebookInstanceUrl. Terminal access yields IMDS credentials for the attached role.",
					"required_permissions": []string{
						"sagemaker:CreatePresignedNotebookInstanceUrl",
					},
				})

				highValueRoles = append(highValueRoles, map[string]any{
					"role_arn":      detail.RoleARN,
					"attached_to":   fmt.Sprintf("notebook/%s", detail.NotebookName),
					"access_method": "presigned_url",
				})
			}

			// Internet-enabled notebooks allow credential exfiltration
			if detail.Status == "InService" && detail.DirectInternetAccess == "Enabled" {
				privescPaths = append(privescPaths, map[string]any{
					"technique":     "NotebookCredentialExfil",
					"severity":      "high",
					"resource_name": detail.NotebookName,
					"resource_arn":  detail.NotebookARN,
					"target_role":   detail.RoleARN,
					"description":   "Internet-enabled notebook allows exfiltrating IMDS credentials to external endpoints.",
					"required_permissions": []string{
						"sagemaker:CreatePresignedNotebookInstanceUrl",
					},
				})
			}

			// Root access notebooks allow deeper persistence
			if detail.RootAccess == "Enabled" {
				privescPaths = append(privescPaths, map[string]any{
					"technique":     "NotebookRootPersistence",
					"severity":      "medium",
					"resource_name": detail.NotebookName,
					"resource_arn":  detail.NotebookARN,
					"target_role":   detail.RoleARN,
					"description":   "Notebook with root access enables system-level persistence (cron jobs, modified packages, kernel backdoors).",
					"required_permissions": []string{
						"sagemaker:CreatePresignedNotebookInstanceUrl",
					},
				})
			}
		}
	}

	// --- Step 2: Studio Domain Presigned URL Targets ---
	prog.Update(2, "Checking Studio domains for presigned URL and role swapping paths")

	domains, err := m.factory.ListSageMakerDomains(bgCtx, creds)
	if err == nil {
		for i, d := range domains {
			if i >= maxItems {
				break
			}
			detail, err := m.factory.DescribeSageMakerDomain(bgCtx, creds, d.DomainID)
			if err != nil {
				continue
			}

			if detail.DefaultExecutionRole != "" {
				roleSet[detail.DefaultExecutionRole] = true

				// Domain presigned URL path
				privescPaths = append(privescPaths, map[string]any{
					"technique":     "PresignedDomainURL",
					"severity":      "high",
					"resource_name": detail.DomainName,
					"resource_arn":  detail.DomainARN,
					"target_role":   detail.DefaultExecutionRole,
					"description":   "Studio domain can be accessed via CreatePresignedDomainUrl. Grants browser session with the profile's ExecutionRole.",
					"required_permissions": []string{
						"sagemaker:CreatePresignedDomainUrl",
					},
				})

				// Domain role swapping path
				privescPaths = append(privescPaths, map[string]any{
					"technique":     "DomainRoleSwap",
					"severity":      "critical",
					"resource_name": detail.DomainName,
					"resource_arn":  detail.DomainARN,
					"target_role":   detail.DefaultExecutionRole,
					"description":   "UpdateDomain can modify DefaultUserSettings.ExecutionRole so new apps inherit an elevated role. Combined with CreateApp + CreatePresignedDomainUrl for full escalation.",
					"required_permissions": []string{
						"sagemaker:UpdateDomain",
						"iam:PassRole",
						"sagemaker:CreateApp",
						"sagemaker:CreatePresignedDomainUrl",
					},
				})

				highValueRoles = append(highValueRoles, map[string]any{
					"role_arn":      detail.DefaultExecutionRole,
					"attached_to":   fmt.Sprintf("domain/%s", detail.DomainID),
					"access_method": "presigned_url",
				})
			}
		}
	}

	// --- Step 3: User Profile Role Targets ---
	prog.Update(3, "Checking user profiles for role modification paths")

	if domains != nil {
		for _, d := range domains {
			profiles, err := m.factory.ListSageMakerUserProfiles(bgCtx, creds, d.DomainID)
			if err != nil {
				continue
			}
			for j, p := range profiles {
				if j >= maxItems {
					break
				}
				detail, err := m.factory.DescribeSageMakerUserProfile(bgCtx, creds, p.DomainID, p.UserProfileName)
				if err != nil {
					continue
				}

				if detail.ExecutionRole != "" {
					roleSet[detail.ExecutionRole] = true

					// Profile-specific role modification
					privescPaths = append(privescPaths, map[string]any{
						"technique":     "UserProfileRoleSwap",
						"severity":      "high",
						"resource_name": fmt.Sprintf("%s/%s", p.DomainID, p.UserProfileName),
						"resource_arn":  detail.UserProfileARN,
						"target_role":   detail.ExecutionRole,
						"description":   "UpdateUserProfile can change execution role to a higher-privilege alternative. Combined with CreateApp + CreatePresignedDomainUrl.",
						"required_permissions": []string{
							"sagemaker:UpdateUserProfile",
							"iam:PassRole",
							"sagemaker:CreateApp",
							"sagemaker:CreatePresignedDomainUrl",
						},
					})
				}
			}
		}
	}

	// --- Step 4: Lifecycle Config Persistence Vectors ---
	prog.Update(4, "Checking lifecycle configs for persistence injection points")

	nbLCCs, err := m.factory.ListSageMakerNotebookLifecycleConfigs(bgCtx, creds)
	if err == nil {
		for _, lcc := range nbLCCs {
			persistenceVectors = append(persistenceVectors, map[string]any{
				"type":          "notebook_lifecycle_config",
				"name":          lcc.Name,
				"arn":           lcc.ARN,
				"creation_time": lcc.CreationTime,
				"description":   "Notebook lifecycle configs run on instance start/create. Can be modified to inject reverse shells or credential exfiltration scripts.",
				"attack_permissions": []string{
					"sagemaker:CreateNotebookInstanceLifecycleConfig",
					"sagemaker:UpdateNotebookInstance",
				},
			})
		}
	}

	studioLCCs, err := m.factory.ListSageMakerStudioLifecycleConfigs(bgCtx, creds)
	if err == nil {
		for _, lcc := range studioLCCs {
			persistenceVectors = append(persistenceVectors, map[string]any{
				"type":          "studio_lifecycle_config",
				"name":          lcc.Name,
				"arn":           lcc.ARN,
				"creation_time": lcc.CreationTime,
				"description":   "Studio lifecycle configs run when apps start. Can inject payloads at domain, user profile, or space level.",
				"attack_permissions": []string{
					"sagemaker:CreateStudioLifecycleConfig",
					"sagemaker:UpdateDomain",
				},
			})
		}
	}

	if len(persistenceVectors) > 0 {
		privescPaths = append(privescPaths, map[string]any{
			"technique":     "LifecycleConfigInjection",
			"severity":      "high",
			"resource_name": fmt.Sprintf("%d lifecycle configs", len(persistenceVectors)),
			"description":   "Existing lifecycle configs can be modified or new ones created and attached to notebooks/domains for persistent code execution on every start.",
			"required_permissions": []string{
				"sagemaker:CreateNotebookInstanceLifecycleConfig",
				"sagemaker:UpdateNotebookInstance",
			},
		})
	}

	// --- Step 5: Training/Processing Job Code Execution ---
	prog.Update(5, "Checking for job-based code execution paths")

	// Unique execution roles are potential iam:PassRole targets for job-based privesc
	for role := range roleSet {
		roleName := role
		if idx := strings.LastIndex(role, "/"); idx >= 0 {
			roleName = role[idx+1:]
		}
		privescPaths = append(privescPaths, map[string]any{
			"technique":     "TrainingJobCodeExec",
			"severity":      "medium",
			"resource_name": roleName,
			"target_role":   role,
			"description":   "CreateTrainingJob with iam:PassRole can launch a training container with this execution role. Container entrypoint can exfiltrate role credentials via IMDS.",
			"required_permissions": []string{
				"sagemaker:CreateTrainingJob",
				"iam:PassRole",
			},
		})
		privescPaths = append(privescPaths, map[string]any{
			"technique":     "ProcessingJobCodeExec",
			"severity":      "medium",
			"resource_name": roleName,
			"target_role":   role,
			"description":   "CreateProcessingJob with iam:PassRole can launch a processing container with this execution role.",
			"required_permissions": []string{
				"sagemaker:CreateProcessingJob",
				"iam:PassRole",
			},
		})
	}

	// Build summary
	techniqueCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	for _, p := range privescPaths {
		if t, ok := p["technique"].(string); ok {
			techniqueCounts[t]++
		}
		if s, ok := p["severity"].(string); ok {
			severityCounts[s]++
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"privesc_paths":       privescPaths,
			"path_count":          len(privescPaths),
			"high_value_roles":    highValueRoles,
			"persistence_vectors": persistenceVectors,
			"summary": map[string]any{
				"total_paths":      len(privescPaths),
				"unique_roles":     len(roleSet),
				"technique_counts": techniqueCounts,
				"severity_counts":  severityCounts,
			},
		},
	}
}

func (m *SageMakerPrivescCheckModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
