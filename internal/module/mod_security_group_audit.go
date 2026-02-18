package module

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// SecurityGroupAuditModule audits EC2 security groups for overly permissive
// ingress rules (0.0.0.0/0 or ::/0) that expose services to the internet.
type SecurityGroupAuditModule struct {
	factory *aws.ClientFactory
}

func (m *SecurityGroupAuditModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ec2.security-group-audit",
		Name:        "Security Group Audit",
		Version:     "1.0.0",
		Description: "Audits all EC2 security groups for overly permissive ingress rules. Identifies groups allowing inbound traffic from 0.0.0.0/0 or ::/0, especially on sensitive ports (SSH, RDP, database ports).",
		Services:    []string{"ec2"},
		RequiredActions: []string{
			"ec2:DescribeSecurityGroups",
		},
		RequiredResources: []string{"arn:aws:ec2:*:*:security-group/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "check_egress", Type: "bool", Default: false, Description: "Also audit egress rules"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "group_count", Type: "int", Description: "Total security groups"},
			{Name: "open_groups", Type: "[]map", Description: "Groups with overly permissive rules"},
			{Name: "sensitive_port_exposure", Type: "[]map", Description: "Groups exposing sensitive ports to the internet"},
			{Name: "findings_count", Type: "int", Description: "Total findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1190/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EC2", SortOrder: 2},
	}
}

func (m *SecurityGroupAuditModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"ec2:DescribeSecurityGroups (paginated)"},
		Confidence:      1.0,
	}
}

func (m *SecurityGroupAuditModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call ec2:DescribeSecurityGroups and analyze each group's ingress rules for overly permissive access patterns.",
		WouldMutate: false,
		APICalls:    []string{"ec2:DescribeSecurityGroups"},
	}
}

// Sensitive ports commonly exposed by misconfiguration
var sensitivePorts = map[int32]string{
	22:    "SSH",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	1433:  "MSSQL",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
	5900:  "VNC",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
}

type sgDetail struct {
	GroupID     string
	GroupName   string
	Description string
	VpcID       string
	Ingress     []ec2types.IpPermission
	Egress      []ec2types.IpPermission
}

func (m *SecurityGroupAuditModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()
	checkEgress := ctx.InputBool("check_egress")

	client := m.factory.EC2Client(creds)
	m.factory.WaitForService("ec2")

	var allGroups []sgDetail
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(bgCtx)
		if err != nil {
			return sdk.ErrResult(fmt.Errorf("describing security groups: %w", err))
		}
		for _, sg := range page.SecurityGroups {
			allGroups = append(allGroups, sgDetail{
				GroupID:     awssdk.ToString(sg.GroupId),
				GroupName:   awssdk.ToString(sg.GroupName),
				Description: awssdk.ToString(sg.Description),
				VpcID:       awssdk.ToString(sg.VpcId),
				Ingress:     sg.IpPermissions,
				Egress:      sg.IpPermissionsEgress,
			})
		}
		m.factory.WaitForService("ec2")
	}

	prog.Total(len(allGroups))

	var openGroups []map[string]any
	var sensitiveExposure []map[string]any

	for i, sg := range allGroups {
		prog.Update(i+1, "Auditing: "+sg.GroupID)

		// Check ingress rules
		for _, perm := range sg.Ingress {
			openCIDRs := findOpenCIDRs(perm)
			if len(openCIDRs) == 0 {
				continue
			}

			fromPort := int32(0)
			toPort := int32(0)
			if perm.FromPort != nil {
				fromPort = *perm.FromPort
			}
			if perm.ToPort != nil {
				toPort = *perm.ToPort
			}

			protocol := awssdk.ToString(perm.IpProtocol)

			finding := map[string]any{
				"group_id":   sg.GroupID,
				"group_name": sg.GroupName,
				"vpc_id":     sg.VpcID,
				"direction":  "ingress",
				"protocol":   protocol,
				"from_port":  fromPort,
				"to_port":    toPort,
				"open_cidrs": openCIDRs,
			}
			openGroups = append(openGroups, finding)

			// Check if sensitive ports are exposed
			if protocol == "-1" {
				sensitiveExposure = append(sensitiveExposure, map[string]any{
					"group_id":   sg.GroupID,
					"group_name": sg.GroupName,
					"service":    "ALL TRAFFIC",
					"severity":   "critical",
				})
			} else {
				for port, svcName := range sensitivePorts {
					if portInRange(port, fromPort, toPort) {
						sensitiveExposure = append(sensitiveExposure, map[string]any{
							"group_id":   sg.GroupID,
							"group_name": sg.GroupName,
							"port":       port,
							"service":    svcName,
							"severity":   portSeverity(port),
						})
					}
				}
			}
		}

		if checkEgress {
			for _, perm := range sg.Egress {
				openCIDRs := findOpenCIDRs(perm)
				if len(openCIDRs) == 0 {
					continue
				}

				fromPort := int32(0)
				toPort := int32(0)
				if perm.FromPort != nil {
					fromPort = *perm.FromPort
				}
				if perm.ToPort != nil {
					toPort = *perm.ToPort
				}

				openGroups = append(openGroups, map[string]any{
					"group_id":   sg.GroupID,
					"group_name": sg.GroupName,
					"vpc_id":     sg.VpcID,
					"direction":  "egress",
					"protocol":   awssdk.ToString(perm.IpProtocol),
					"from_port":  fromPort,
					"to_port":    toPort,
					"open_cidrs": openCIDRs,
				})
			}
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"group_count":             len(allGroups),
			"open_groups":             openGroups,
			"sensitive_port_exposure": sensitiveExposure,
			"findings_count":          len(openGroups) + len(sensitiveExposure),
		},
	}
}

func (m *SecurityGroupAuditModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

func findOpenCIDRs(perm ec2types.IpPermission) []string {
	var open []string
	for _, ipRange := range perm.IpRanges {
		cidr := awssdk.ToString(ipRange.CidrIp)
		if cidr == "0.0.0.0/0" {
			open = append(open, cidr)
		}
	}
	for _, ipv6Range := range perm.Ipv6Ranges {
		cidr := awssdk.ToString(ipv6Range.CidrIpv6)
		if cidr == "::/0" {
			open = append(open, cidr)
		}
	}
	return open
}

func portInRange(port, from, to int32) bool {
	if from == 0 && to == 0 {
		return true
	}
	return port >= from && port <= to
}

func portSeverity(port int32) string {
	switch port {
	case 22, 3389:
		return "high"
	case 3306, 5432, 1433, 27017, 6379:
		return "critical"
	default:
		return "medium"
	}
}
