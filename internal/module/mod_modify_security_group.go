package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// ModifySecurityGroupModule adds an ingress rule to an EC2 security group.
// This is a write-risk module used for defense evasion / firewall modification testing (T1562.007).
type ModifySecurityGroupModule struct {
	factory *aws.ClientFactory
}

func (m *ModifySecurityGroupModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ec2.modify-security-group",
		Name:        "Modify Security Group",
		Version:     "1.0.0",
		Description: "Adds an ingress rule to an EC2 security group. Used for testing firewall modification and network access expansion. Adds a single TCP ingress rule to the specified security group.",
		Services:    []string{"ec2"},
		RequiredActions: []string{
			"ec2:AuthorizeSecurityGroupIngress",
		},
		RequiredResources: []string{"arn:aws:ec2:*:*:security-group/*"},
		RiskClass:         sdk.RiskWrite,
		Inputs: []sdk.InputSpec{
			{Name: "group_id", Type: "string", Description: "Security group ID (sg-...)", Required: true},
			{Name: "protocol", Type: "string", Default: "tcp", Description: "IP protocol (tcp, udp, icmp, -1 for all)"},
			{Name: "from_port", Type: "int", Default: 443, Description: "Start of port range"},
			{Name: "to_port", Type: "int", Default: 443, Description: "End of port range"},
			{Name: "cidr_ip", Type: "string", Default: "0.0.0.0/0", Description: "CIDR IP range to allow"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "group_id", Type: "string", Description: "The modified security group ID"},
			{Name: "rule_added", Type: "map", Description: "Details of the ingress rule added"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1562/007/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EC2", SortOrder: 3},
	}
}

func (m *ModifySecurityGroupModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	groupID := ctx.InputString("group_id")
	if groupID == "" {
		return sdk.PreflightResult{
			MissingPermissions: []string{"(group_id input is required)"},
			PlannedAPICalls:    []string{"ec2:AuthorizeSecurityGroupIngress"},
			Confidence:         0.0,
		}
	}
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"ec2:AuthorizeSecurityGroupIngress"},
		Confidence:      1.0,
	}
}

func (m *ModifySecurityGroupModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	groupID := ctx.InputString("group_id")
	protocol := ctx.InputString("protocol")
	if protocol == "" {
		protocol = "tcp"
	}
	fromPort := ctx.InputInt("from_port")
	toPort := ctx.InputInt("to_port")
	cidrIP := ctx.InputString("cidr_ip")
	if cidrIP == "" {
		cidrIP = "0.0.0.0/0"
	}

	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would call ec2:AuthorizeSecurityGroupIngress on %s to add %s port %d-%d from %s.",
			groupID, protocol, fromPort, toPort, cidrIP),
		WouldMutate: true,
		APICalls:    []string{"ec2:AuthorizeSecurityGroupIngress"},
	}
}

func (m *ModifySecurityGroupModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	groupID := ctx.InputString("group_id")
	if groupID == "" {
		return sdk.ErrResult(fmt.Errorf("group_id input is required"))
	}

	protocol := ctx.InputString("protocol")
	if protocol == "" {
		protocol = "tcp"
	}
	fromPort := int32(ctx.InputInt("from_port"))
	toPort := int32(ctx.InputInt("to_port"))
	cidrIP := ctx.InputString("cidr_ip")
	if cidrIP == "" {
		cidrIP = "0.0.0.0/0"
	}

	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	prog.Total(1)
	prog.Update(1, fmt.Sprintf("Adding ingress rule to %s", groupID))

	result, err := m.factory.AuthorizeSecurityGroupIngress(bgCtx, creds, groupID, protocol, cidrIP, fromPort, toPort)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("authorizing ingress: %w", err))
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"group_id": result.GroupID,
			"rule_added": map[string]any{
				"protocol":  result.Protocol,
				"from_port": result.FromPort,
				"to_port":   result.ToPort,
				"cidr_ip":   result.CidrIP,
			},
		},
	}
}

func (m *ModifySecurityGroupModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	// Write ops are not idempotent — return prior outputs instead of re-executing
	return sdk.RunResult{Outputs: prior.Outputs}
}
