package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// RDSEnumerateModule lists RDS database instances and snapshots,
// identifying publicly accessible databases and unencrypted resources.
type RDSEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *RDSEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.rds.enumerate-instances",
		Name:        "Enumerate RDS Instances",
		Version:     "1.0.0",
		Description: "Lists all RDS database instances and snapshots in the target region. Identifies publicly accessible databases, unencrypted instances, and snapshots that could be restored for data access. Extracts master usernames, endpoints, and engine versions.",
		Services:    []string{"rds"},
		RequiredActions: []string{
			"rds:DescribeDBInstances",
			"rds:DescribeDBSnapshots",
		},
		RequiredResources: []string{"arn:aws:rds:*:*:db:*", "arn:aws:rds:*:*:snapshot:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "include_snapshots", Type: "bool", Default: true, Description: "Also enumerate RDS snapshots"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "instance_count", Type: "int", Description: "Total RDS instances found"},
			{Name: "instances", Type: "[]map", Description: "RDS instance details"},
			{Name: "public_instances", Type: "[]string", Description: "Publicly accessible instances"},
			{Name: "unencrypted_instances", Type: "[]string", Description: "Instances without encryption"},
			{Name: "snapshot_count", Type: "int", Description: "Total RDS snapshots found"},
			{Name: "unencrypted_snapshots", Type: "[]string", Description: "Snapshots without encryption"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "RDS", SortOrder: 1},
	}
}

func (m *RDSEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"rds:DescribeDBInstances (paginated)"}
	if ctx.InputBool("include_snapshots") {
		calls = append(calls, "rds:DescribeDBSnapshots (paginated)")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *RDSEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would call rds:DescribeDBInstances to enumerate all RDS databases."
	if ctx.InputBool("include_snapshots") {
		desc += " Would also call rds:DescribeDBSnapshots to enumerate snapshots."
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls:    []string{"rds:DescribeDBInstances", "rds:DescribeDBSnapshots"},
	}
}

func (m *RDSEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	// Enumerate instances
	instances, err := m.factory.ListRDSInstances(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing RDS instances: %w", err))
	}

	steps := len(instances)
	includeSnapshots := ctx.InputBool("include_snapshots")
	if includeSnapshots {
		steps += 1 // one step for snapshot enumeration
	}
	prog.Total(steps)

	var instanceDetails []map[string]any
	var publicInstances []string
	var unencryptedInstances []string

	for i, inst := range instances {
		prog.Update(i+1, "Processing: "+inst.DBInstanceID)

		entry := map[string]any{
			"db_instance_id":      inst.DBInstanceID,
			"engine":              inst.Engine,
			"engine_version":      inst.EngineVersion,
			"instance_class":      inst.InstanceClass,
			"endpoint":            inst.Endpoint,
			"port":                inst.Port,
			"master_username":     inst.MasterUsername,
			"publicly_accessible": inst.PublicAccess,
			"encrypted":           inst.Encrypted,
			"status":              inst.Status,
			"multi_az":            inst.MultiAZ,
		}

		if inst.PublicAccess {
			publicInstances = append(publicInstances, inst.DBInstanceID)
			entry["risk_level"] = "high"
		}

		if !inst.Encrypted {
			unencryptedInstances = append(unencryptedInstances, inst.DBInstanceID)
		}

		instanceDetails = append(instanceDetails, entry)
	}

	outputs := map[string]any{
		"instance_count":        len(instances),
		"instances":             instanceDetails,
		"public_instances":      publicInstances,
		"unencrypted_instances": unencryptedInstances,
	}

	// Enumerate snapshots
	if includeSnapshots {
		prog.Update(len(instances)+1, "Enumerating snapshots")
		snapshots, err := m.factory.ListRDSSnapshots(bgCtx, creds)
		if err == nil {
			var unencryptedSnapshots []string
			for _, snap := range snapshots {
				if !snap.Encrypted {
					unencryptedSnapshots = append(unencryptedSnapshots, snap.SnapshotID)
				}
			}
			outputs["snapshot_count"] = len(snapshots)
			outputs["unencrypted_snapshots"] = unencryptedSnapshots
		}
	}

	return sdk.RunResult{Outputs: outputs}
}

func (m *RDSEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
