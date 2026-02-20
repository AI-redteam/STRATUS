package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// SageMakerEnumerateModule discovers SageMaker Studio domains, notebook instances,
// user profiles, models, endpoints, and training jobs. Identifies attack surfaces
// such as internet-enabled notebooks, root-access instances, and execution roles.
type SageMakerEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *SageMakerEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.sagemaker.enumerate",
		Name:        "Enumerate SageMaker Resources",
		Version:     "1.0.0",
		Description: "Comprehensive enumeration of SageMaker Studio domains, user profiles, notebook instances, models, endpoints, and training jobs. Extracts execution roles, network configurations, and security settings. Identifies notebooks with direct internet access, root access enabled, and attached lifecycle configurations that may contain persistence mechanisms.",
		Services:    []string{"sagemaker"},
		RequiredActions: []string{
			"sagemaker:ListDomains",
			"sagemaker:DescribeDomain",
			"sagemaker:ListUserProfiles",
			"sagemaker:DescribeUserProfile",
			"sagemaker:ListNotebookInstances",
			"sagemaker:DescribeNotebookInstance",
			"sagemaker:ListModels",
			"sagemaker:ListEndpoints",
			"sagemaker:ListTrainingJobs",
			"sagemaker:ListNotebookInstanceLifecycleConfigs",
			"sagemaker:ListStudioLifecycleConfigs",
		},
		RequiredResources: []string{"arn:aws:sagemaker:*:*:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "include_notebooks", Type: "bool", Default: true, Description: "Enumerate notebook instances with detailed inspection"},
			{Name: "include_domains", Type: "bool", Default: true, Description: "Enumerate Studio domains and user profiles"},
			{Name: "include_models", Type: "bool", Default: true, Description: "Enumerate models, endpoints, and training jobs"},
			{Name: "include_lifecycle_configs", Type: "bool", Default: true, Description: "List lifecycle configurations (persistence indicators)"},
			{Name: "max_items", Type: "int", Default: 100, Description: "Maximum items per resource type"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "domains", Type: "[]map", Description: "Studio domain details"},
			{Name: "user_profiles", Type: "[]map", Description: "User profile details"},
			{Name: "notebooks", Type: "[]map", Description: "Notebook instance details"},
			{Name: "models", Type: "[]map", Description: "Model summaries"},
			{Name: "endpoints", Type: "[]map", Description: "Endpoint summaries"},
			{Name: "training_jobs", Type: "[]map", Description: "Training job summaries"},
			{Name: "lifecycle_configs", Type: "[]map", Description: "Lifecycle configs (notebook + studio)"},
			{Name: "execution_roles", Type: "[]string", Description: "Unique execution role ARNs discovered"},
			{Name: "findings", Type: "[]map", Description: "Security findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1059/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "SageMaker", SortOrder: 1},
	}
}

func (m *SageMakerEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	var calls []string
	if ctx.InputBool("include_domains") {
		calls = append(calls, "sagemaker:ListDomains", "sagemaker:DescribeDomain", "sagemaker:ListUserProfiles")
	}
	if ctx.InputBool("include_notebooks") {
		calls = append(calls, "sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance")
	}
	if ctx.InputBool("include_models") {
		calls = append(calls, "sagemaker:ListModels", "sagemaker:ListEndpoints", "sagemaker:ListTrainingJobs")
	}
	if ctx.InputBool("include_lifecycle_configs") {
		calls = append(calls, "sagemaker:ListNotebookInstanceLifecycleConfigs", "sagemaker:ListStudioLifecycleConfigs")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *SageMakerEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate SageMaker resources including Studio domains, notebook instances, models, endpoints, training jobs, and lifecycle configurations.",
		WouldMutate: false,
		APICalls:    []string{"sagemaker:ListDomains", "sagemaker:ListNotebookInstances", "sagemaker:ListModels", "sagemaker:ListEndpoints", "sagemaker:ListTrainingJobs"},
	}
}

func (m *SageMakerEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxItems := ctx.InputInt("max_items")
	if maxItems <= 0 {
		maxItems = 100
	}

	roleSet := make(map[string]bool)
	var findings []map[string]any
	var domainResults []map[string]any
	var profileResults []map[string]any
	var notebookResults []map[string]any
	var modelResults []map[string]any
	var endpointResults []map[string]any
	var trainingResults []map[string]any
	var lifecycleResults []map[string]any

	steps := 0
	if ctx.InputBool("include_domains") {
		steps += 2
	}
	if ctx.InputBool("include_notebooks") {
		steps++
	}
	if ctx.InputBool("include_models") {
		steps += 3
	}
	if ctx.InputBool("include_lifecycle_configs") {
		steps += 2
	}
	prog.Total(steps)
	step := 0

	// --- Studio Domains ---
	if ctx.InputBool("include_domains") {
		step++
		prog.Update(step, "Listing Studio domains")

		domains, err := m.factory.ListSageMakerDomains(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "domains", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list domains: %v", err),
			})
		} else {
			for i, d := range domains {
				if i >= maxItems {
					break
				}
				detail, err := m.factory.DescribeSageMakerDomain(bgCtx, creds, d.DomainID)
				if err != nil {
					domainResults = append(domainResults, map[string]any{
						"domain_id":   d.DomainID,
						"domain_name": d.DomainName,
						"status":      d.Status,
					})
					continue
				}

				if detail.DefaultExecutionRole != "" {
					roleSet[detail.DefaultExecutionRole] = true
				}

				entry := map[string]any{
					"domain_id":              detail.DomainID,
					"domain_name":            detail.DomainName,
					"domain_arn":             detail.DomainARN,
					"status":                 detail.Status,
					"auth_mode":              detail.AuthMode,
					"default_execution_role": detail.DefaultExecutionRole,
					"vpc_id":                 detail.VpcID,
					"subnet_ids":             detail.SubnetIDs,
					"security_group_ids":     detail.SecurityGroupIDs,
					"home_efs":               detail.HomeEFSFileSystemID,
					"app_network_access":     detail.AppNetworkAccessType,
				}
				domainResults = append(domainResults, entry)

				// Flag public network access
				if detail.AppNetworkAccessType == "PublicInternetOnly" {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("domain/%s", detail.DomainID),
						"finding":  "PublicNetworkAccess",
						"severity": "medium",
						"detail":   fmt.Sprintf("Domain %s has PublicInternetOnly network access. Apps can reach the internet directly.", detail.DomainName),
					})
				}
			}
		}

		// --- User Profiles ---
		step++
		prog.Update(step, "Listing user profiles")

		for _, d := range domainResults {
			domainID, _ := d["domain_id"].(string)
			if domainID == "" {
				continue
			}
			profiles, err := m.factory.ListSageMakerUserProfiles(bgCtx, creds, domainID)
			if err != nil {
				continue
			}
			for j, p := range profiles {
				if j >= maxItems {
					break
				}
				profileEntry := map[string]any{
					"user_profile_name": p.UserProfileName,
					"domain_id":         p.DomainID,
					"status":            p.Status,
				}

				detail, err := m.factory.DescribeSageMakerUserProfile(bgCtx, creds, p.DomainID, p.UserProfileName)
				if err == nil && detail.ExecutionRole != "" {
					profileEntry["execution_role"] = detail.ExecutionRole
					roleSet[detail.ExecutionRole] = true
				}

				profileResults = append(profileResults, profileEntry)
			}
		}
	}

	// --- Notebook Instances ---
	if ctx.InputBool("include_notebooks") {
		step++
		prog.Update(step, "Listing notebook instances")

		notebooks, err := m.factory.ListSageMakerNotebookInstances(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "notebooks", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list notebook instances: %v", err),
			})
		} else {
			for i, nb := range notebooks {
				if i >= maxItems {
					break
				}
				detail, err := m.factory.DescribeSageMakerNotebookInstance(bgCtx, creds, nb.NotebookName)
				if err != nil {
					notebookResults = append(notebookResults, map[string]any{
						"notebook_name": nb.NotebookName,
						"status":        nb.Status,
						"instance_type": nb.InstanceType,
					})
					continue
				}

				if detail.RoleARN != "" {
					roleSet[detail.RoleARN] = true
				}

				entry := map[string]any{
					"notebook_name":          detail.NotebookName,
					"notebook_arn":           detail.NotebookARN,
					"status":                 detail.Status,
					"instance_type":          detail.InstanceType,
					"role_arn":               detail.RoleARN,
					"direct_internet_access": detail.DirectInternetAccess,
					"root_access":            detail.RootAccess,
					"default_code_repo":      detail.DefaultCodeRepo,
					"lifecycle_config":        detail.LifecycleConfig,
					"url":                    detail.URL,
				}
				notebookResults = append(notebookResults, entry)

				// Flag security issues
				if detail.DirectInternetAccess == "Enabled" {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("notebook/%s", detail.NotebookName),
						"finding":  "DirectInternetAccess",
						"severity": "medium",
						"detail":   fmt.Sprintf("Notebook %s has direct internet access enabled. Data exfiltration possible.", detail.NotebookName),
					})
				}
				if detail.RootAccess == "Enabled" {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("notebook/%s", detail.NotebookName),
						"finding":  "RootAccessEnabled",
						"severity": "medium",
						"detail":   fmt.Sprintf("Notebook %s has root access enabled. Users can modify system packages and install persistence.", detail.NotebookName),
					})
				}
				if detail.LifecycleConfig != "" {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("notebook/%s", detail.NotebookName),
						"finding":  "LifecycleConfigAttached",
						"severity": "info",
						"detail":   fmt.Sprintf("Notebook %s has lifecycle config %s attached. Inspect for persistence scripts.", detail.NotebookName, detail.LifecycleConfig),
					})
				}
			}
		}
	}

	// --- Models, Endpoints, Training Jobs ---
	if ctx.InputBool("include_models") {
		step++
		prog.Update(step, "Listing models")
		models, err := m.factory.ListSageMakerModels(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "models", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list models: %v", err),
			})
		} else {
			for i, model := range models {
				if i >= maxItems {
					break
				}
				modelResults = append(modelResults, map[string]any{
					"model_name":    model.ModelName,
					"model_arn":     model.ModelARN,
					"creation_time": model.CreationTime,
				})
			}
		}

		step++
		prog.Update(step, "Listing endpoints")
		endpoints, err := m.factory.ListSageMakerEndpoints(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "endpoints", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list endpoints: %v", err),
			})
		} else {
			for i, ep := range endpoints {
				if i >= maxItems {
					break
				}
				endpointResults = append(endpointResults, map[string]any{
					"endpoint_name": ep.EndpointName,
					"endpoint_arn":  ep.EndpointARN,
					"status":        ep.Status,
					"creation_time": ep.CreationTime,
				})
			}
		}

		step++
		prog.Update(step, "Listing training jobs")
		jobs, err := m.factory.ListSageMakerTrainingJobs(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "training_jobs", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list training jobs: %v", err),
			})
		} else {
			for i, job := range jobs {
				if i >= maxItems {
					break
				}
				trainingResults = append(trainingResults, map[string]any{
					"training_job_name": job.TrainingJobName,
					"training_job_arn":  job.TrainingJobARN,
					"status":            job.Status,
					"creation_time":     job.CreationTime,
				})
			}
		}
	}

	// --- Lifecycle Configs ---
	if ctx.InputBool("include_lifecycle_configs") {
		step++
		prog.Update(step, "Listing notebook lifecycle configs")
		nbLCCs, err := m.factory.ListSageMakerNotebookLifecycleConfigs(bgCtx, creds)
		if err == nil {
			for i, lcc := range nbLCCs {
				if i >= maxItems {
					break
				}
				lifecycleResults = append(lifecycleResults, map[string]any{
					"name":          lcc.Name,
					"arn":           lcc.ARN,
					"type":          "notebook",
					"creation_time": lcc.CreationTime,
				})
			}
		}

		step++
		prog.Update(step, "Listing studio lifecycle configs")
		studioLCCs, err := m.factory.ListSageMakerStudioLifecycleConfigs(bgCtx, creds)
		if err == nil {
			for i, lcc := range studioLCCs {
				if i >= maxItems {
					break
				}
				lifecycleResults = append(lifecycleResults, map[string]any{
					"name":          lcc.Name,
					"arn":           lcc.ARN,
					"type":          "studio",
					"creation_time": lcc.CreationTime,
				})
			}
		}

		if len(lifecycleResults) > 0 {
			findings = append(findings, map[string]any{
				"resource": "lifecycle_configs",
				"finding":  "LifecycleConfigsPresent",
				"severity": "info",
				"detail":   fmt.Sprintf("Found %d lifecycle configurations. These execute on notebook/app start and could contain persistence mechanisms (reverse shells, cron jobs, credential exfiltration).", len(lifecycleResults)),
			})
		}
	}

	var roles []string
	for r := range roleSet {
		roles = append(roles, r)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"domains":           domainResults,
			"user_profiles":     profileResults,
			"notebooks":         notebookResults,
			"models":            modelResults,
			"endpoints":         endpointResults,
			"training_jobs":     trainingResults,
			"lifecycle_configs": lifecycleResults,
			"execution_roles":   roles,
			"findings":          findings,
		},
	}
}

func (m *SageMakerEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
