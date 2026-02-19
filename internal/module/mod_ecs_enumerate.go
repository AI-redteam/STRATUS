package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// ECSEnumerateModule lists ECS clusters, services, and running tasks.
// Identifies task definitions that may contain credentials in environment
// variables or grant access to sensitive IAM roles.
type ECSEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *ECSEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ecs.enumerate-clusters",
		Name:        "Enumerate ECS Clusters",
		Version:     "1.0.0",
		Description: "Lists all ECS clusters and their running tasks in the target region. Identifies task definitions, launch types, and resource allocations. Running tasks may expose container credentials or provide lateral movement paths via task IAM roles.",
		Services:    []string{"ecs"},
		RequiredActions: []string{
			"ecs:ListClusters",
			"ecs:DescribeClusters",
			"ecs:ListTasks",
			"ecs:DescribeTasks",
		},
		RequiredResources: []string{"arn:aws:ecs:*:*:cluster/*", "arn:aws:ecs:*:*:task/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "include_tasks", Type: "bool", Default: true, Description: "Also enumerate running tasks per cluster"},
			{Name: "max_clusters", Type: "int", Default: 50, Description: "Maximum clusters to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "cluster_count", Type: "int", Description: "Total clusters found"},
			{Name: "clusters", Type: "[]map", Description: "Cluster details with task information"},
			{Name: "total_running_tasks", Type: "int", Description: "Total running tasks across all clusters"},
			{Name: "task_definitions_found", Type: "[]string", Description: "Unique task definition ARNs in use"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1610/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "ECS", SortOrder: 1},
	}
}

func (m *ECSEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"ecs:ListClusters", "ecs:DescribeClusters"}
	if ctx.InputBool("include_tasks") {
		calls = append(calls, "ecs:ListTasks (per cluster)", "ecs:DescribeTasks (per cluster)")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *ECSEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would call ecs:ListClusters and ecs:DescribeClusters to enumerate all ECS clusters."
	if ctx.InputBool("include_tasks") {
		desc += " Would also list and describe running tasks in each cluster."
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls:    []string{"ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListTasks", "ecs:DescribeTasks"},
	}
}

func (m *ECSEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	clusters, err := m.factory.ListECSClusters(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing ECS clusters: %w", err))
	}

	maxClusters := ctx.InputInt("max_clusters")
	if maxClusters <= 0 {
		maxClusters = 50
	}
	if len(clusters) > maxClusters {
		clusters = clusters[:maxClusters]
	}

	includeTasks := ctx.InputBool("include_tasks")
	prog.Total(len(clusters))

	var results []map[string]any
	totalRunningTasks := 0
	taskDefSet := make(map[string]bool)

	for i, cluster := range clusters {
		prog.Update(i+1, "Processing: "+cluster.ClusterName)

		entry := map[string]any{
			"cluster_arn":            cluster.ClusterARN,
			"cluster_name":          cluster.ClusterName,
			"status":                cluster.Status,
			"running_tasks":         cluster.RunningTaskCount,
			"active_services":       cluster.ActiveServicesCount,
			"registered_containers": cluster.RegisteredContainers,
		}

		totalRunningTasks += int(cluster.RunningTaskCount)

		if includeTasks && cluster.RunningTaskCount > 0 {
			tasks, err := m.factory.ListECSTasks(bgCtx, creds, cluster.ClusterARN)
			if err == nil {
				var taskSummaries []map[string]any
				for _, task := range tasks {
					taskDefSet[task.TaskDefinitionARN] = true
					taskSummaries = append(taskSummaries, map[string]any{
						"task_arn":           task.TaskARN,
						"task_definition":    task.TaskDefinitionARN,
						"last_status":        task.LastStatus,
						"launch_type":        task.LaunchType,
						"cpu":                task.CPU,
						"memory":             task.Memory,
					})
				}
				entry["tasks"] = taskSummaries
			}
		}

		results = append(results, entry)
	}

	var taskDefs []string
	for td := range taskDefSet {
		taskDefs = append(taskDefs, td)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"cluster_count":         len(clusters),
			"clusters":              results,
			"total_running_tasks":   totalRunningTasks,
			"task_definitions_found": taskDefs,
		},
	}
}

func (m *ECSEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
