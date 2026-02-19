package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EBSEnumerateSnapshotsModule lists EBS snapshots owned by the account,
// identifying unencrypted snapshots that could be restored for data access.
type EBSEnumerateSnapshotsModule struct {
	factory *aws.ClientFactory
}

func (m *EBSEnumerateSnapshotsModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ebs.enumerate-snapshots",
		Name:        "Enumerate EBS Snapshots",
		Version:     "1.0.0",
		Description: "Lists all EBS snapshots owned by the current account. Identifies unencrypted snapshots that could be attached to an attacker-controlled instance for data extraction. Snapshots often contain filesystem data, database files, and application secrets.",
		Services:    []string{"ec2"},
		RequiredActions: []string{
			"ec2:DescribeSnapshots",
		},
		RequiredResources: []string{"arn:aws:ec2:*:*:snapshot/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_snapshots", Type: "int", Default: 500, Description: "Maximum snapshots to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "snapshot_count", Type: "int", Description: "Total snapshots found"},
			{Name: "snapshots", Type: "[]map", Description: "Snapshot details"},
			{Name: "unencrypted_count", Type: "int", Description: "Count of unencrypted snapshots"},
			{Name: "unencrypted_snapshots", Type: "[]string", Description: "Unencrypted snapshot IDs"},
			{Name: "total_volume_gb", Type: "int", Description: "Total volume size in GB"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EBS", SortOrder: 1},
	}
}

func (m *EBSEnumerateSnapshotsModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"ec2:DescribeSnapshots (paginated, owner=self)"},
		Confidence:      1.0,
	}
}

func (m *EBSEnumerateSnapshotsModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call ec2:DescribeSnapshots with owner=self to list all account-owned EBS snapshots.",
		WouldMutate: false,
		APICalls:    []string{"ec2:DescribeSnapshots"},
	}
}

func (m *EBSEnumerateSnapshotsModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	snapshots, err := m.factory.ListEBSSnapshots(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing EBS snapshots: %w", err))
	}

	maxSnapshots := ctx.InputInt("max_snapshots")
	if maxSnapshots <= 0 {
		maxSnapshots = 500
	}
	if len(snapshots) > maxSnapshots {
		snapshots = snapshots[:maxSnapshots]
	}

	prog.Total(len(snapshots))

	var details []map[string]any
	var unencryptedSnaps []string
	unencryptedCount := 0
	var totalVolumeGB int32

	for i, snap := range snapshots {
		prog.Update(i+1, "Processing: "+snap.SnapshotID)

		entry := map[string]any{
			"snapshot_id":    snap.SnapshotID,
			"volume_id":     snap.VolumeID,
			"state":         snap.State,
			"volume_size_gb": snap.VolumeSize,
			"description":   snap.Description,
			"encrypted":     snap.Encrypted,
			"owner_id":      snap.OwnerID,
			"start_time":    snap.StartTime,
		}

		totalVolumeGB += snap.VolumeSize

		if !snap.Encrypted {
			unencryptedCount++
			unencryptedSnaps = append(unencryptedSnaps, snap.SnapshotID)
			entry["risk_level"] = "high"
		}

		details = append(details, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"snapshot_count":        len(snapshots),
			"snapshots":            details,
			"unencrypted_count":    unencryptedCount,
			"unencrypted_snapshots": unencryptedSnaps,
			"total_volume_gb":      totalVolumeGB,
		},
	}
}

func (m *EBSEnumerateSnapshotsModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
