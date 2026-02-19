package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CloudWatchEnumerateLogsModule lists CloudWatch log groups to identify
// logging configuration, data retention, and potential log sources.
type CloudWatchEnumerateLogsModule struct {
	factory *aws.ClientFactory
}

func (m *CloudWatchEnumerateLogsModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.cloudwatch.enumerate-logs",
		Name:        "Enumerate CloudWatch Log Groups",
		Version:     "1.0.0",
		Description: "Lists all CloudWatch log groups in the target region, identifying logging configuration, data volume, and retention settings. Useful for understanding the monitoring posture and identifying log sources that may contain sensitive data.",
		Services:    []string{"logs"},
		RequiredActions: []string{
			"logs:DescribeLogGroups",
		},
		RequiredResources: []string{"arn:aws:logs:*:*:log-group:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "prefix", Type: "string", Default: "", Description: "Log group name prefix filter"},
			{Name: "max_groups", Type: "int", Default: 500, Description: "Maximum log groups to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "log_group_count", Type: "int", Description: "Total log groups found"},
			{Name: "log_groups", Type: "[]map", Description: "Log group details"},
			{Name: "total_stored_bytes", Type: "int", Description: "Total bytes stored across all groups"},
			{Name: "no_retention_count", Type: "int", Description: "Groups with no retention policy (infinite retention)"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "CloudWatch", SortOrder: 1},
	}
}

func (m *CloudWatchEnumerateLogsModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"logs:DescribeLogGroups (paginated)"},
		Confidence:      1.0,
	}
}

func (m *CloudWatchEnumerateLogsModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	prefix := ctx.InputString("prefix")
	desc := "Would call logs:DescribeLogGroups to enumerate all log groups."
	if prefix != "" {
		desc = fmt.Sprintf("Would call logs:DescribeLogGroups with prefix %q.", prefix)
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls:    []string{"logs:DescribeLogGroups"},
	}
}

func (m *CloudWatchEnumerateLogsModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	prefix := ctx.InputString("prefix")
	maxGroups := ctx.InputInt("max_groups")
	if maxGroups <= 0 {
		maxGroups = 500
	}

	groups, err := m.factory.ListLogGroups(bgCtx, creds, prefix)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing log groups: %w", err))
	}

	if len(groups) > maxGroups {
		groups = groups[:maxGroups]
	}

	prog.Total(len(groups))

	var results []map[string]any
	var totalStoredBytes int64
	noRetentionCount := 0

	for i, group := range groups {
		prog.Update(i+1, "Processing: "+group.Name)

		entry := map[string]any{
			"name":           group.Name,
			"arn":            group.ARN,
			"stored_bytes":   group.StoredBytes,
			"retention_days": group.RetentionDays,
			"creation_time":  group.CreationTime,
		}

		totalStoredBytes += group.StoredBytes

		if group.RetentionDays == 0 {
			noRetentionCount++
			entry["retention_policy"] = "never_expire"
		}

		results = append(results, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"log_group_count":    len(results),
			"log_groups":         results,
			"total_stored_bytes": totalStoredBytes,
			"no_retention_count": noRetentionCount,
		},
	}
}

func (m *CloudWatchEnumerateLogsModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
