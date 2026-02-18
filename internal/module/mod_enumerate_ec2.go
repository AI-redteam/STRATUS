package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EnumerateEC2Module lists all EC2 instances with their state, network
// configuration, and security group associations.
type EnumerateEC2Module struct {
	factory *aws.ClientFactory
}

func (m *EnumerateEC2Module) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ec2.enumerate-instances",
		Name:        "Enumerate EC2 Instances",
		Version:     "1.0.0",
		Description: "Lists all EC2 instances in the target region with their state, instance type, network configuration (public/private IPs), and launch time. Identifies instances with public IP addresses.",
		Services:    []string{"ec2"},
		RequiredActions: []string{
			"ec2:DescribeInstances",
		},
		RequiredResources: []string{"arn:aws:ec2:*:*:instance/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs:            []sdk.InputSpec{},
		Outputs: []sdk.OutputSpec{
			{Name: "instance_count", Type: "int", Description: "Total instances found"},
			{Name: "instances", Type: "[]map", Description: "Instance details"},
			{Name: "public_instances", Type: "[]string", Description: "Instance IDs with public IPs"},
			{Name: "state_summary", Type: "map", Description: "Instance state distribution"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1580/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EC2", SortOrder: 1},
	}
}

func (m *EnumerateEC2Module) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"ec2:DescribeInstances (paginated)"},
		Confidence:      1.0,
	}
}

func (m *EnumerateEC2Module) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call ec2:DescribeInstances to enumerate all instances and their network configuration.",
		WouldMutate: false,
		APICalls:    []string{"ec2:DescribeInstances"},
	}
}

func (m *EnumerateEC2Module) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	instances, err := m.factory.ListEC2Instances(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing EC2 instances: %w", err))
	}

	prog.Total(len(instances))

	stateSummary := make(map[string]int)
	var publicInstances []string
	var details []map[string]any

	for i, inst := range instances {
		prog.Update(i+1, "Enumerated: "+inst.InstanceID)

		stateSummary[inst.State]++

		if inst.PublicIP != "" {
			publicInstances = append(publicInstances, inst.InstanceID)
		}

		details = append(details, map[string]any{
			"instance_id":   inst.InstanceID,
			"state":         inst.State,
			"instance_type": inst.InstanceType,
			"private_ip":    inst.PrivateIP,
			"public_ip":     inst.PublicIP,
			"name":          inst.Name,
			"launch_time":   inst.LaunchTime,
		})
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"instance_count":   len(instances),
			"instances":        details,
			"public_instances": publicInstances,
			"state_summary":    stateSummary,
		},
	}
}

func (m *EnumerateEC2Module) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
