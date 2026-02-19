package module

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EC2UserDataExtractModule extracts EC2 instance user data, which often
// contains credentials, bootstrap scripts, and configuration secrets.
type EC2UserDataExtractModule struct {
	factory *aws.ClientFactory
}

func (m *EC2UserDataExtractModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.ec2.userdata-extract",
		Name:        "Extract EC2 User Data",
		Version:     "1.0.0",
		Description: "Extracts user data from EC2 instances. User data often contains bootstrap scripts with embedded credentials, API keys, database passwords, and configuration data. Maps to credential harvesting from cloud compute instances.",
		Services:    []string{"ec2"},
		RequiredActions: []string{
			"ec2:DescribeInstances",
			"ec2:DescribeInstanceAttribute",
		},
		RequiredResources: []string{"arn:aws:ec2:*:*:instance/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "instance_id", Type: "string", Description: "Specific instance ID (leave empty to check all instances)"},
			{Name: "max_instances", Type: "int", Default: 100, Description: "Maximum instances to check"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "instances_checked", Type: "int", Description: "Total instances checked"},
			{Name: "instances_with_userdata", Type: "int", Description: "Instances that have user data"},
			{Name: "results", Type: "[]map", Description: "Per-instance user data results"},
			{Name: "credential_indicators", Type: "[]string", Description: "Instances with potential credentials in user data"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1552/005/",
			"https://attack.mitre.org/techniques/T1059/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EC2", SortOrder: 3},
	}
}

func (m *EC2UserDataExtractModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"ec2:DescribeInstances (paginated)",
			"ec2:DescribeInstanceAttribute (per instance, attribute=userData)",
		},
		Confidence: 1.0,
	}
}

func (m *EC2UserDataExtractModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	instanceID := ctx.InputString("instance_id")
	if instanceID != "" {
		return sdk.DryRunResult{
			Description: fmt.Sprintf("Would call ec2:DescribeInstanceAttribute on instance %s to retrieve user data.", instanceID),
			WouldMutate: false,
			APICalls:    []string{"ec2:DescribeInstanceAttribute"},
		}
	}
	return sdk.DryRunResult{
		Description: "Would enumerate all EC2 instances, then call ec2:DescribeInstanceAttribute for each to extract user data.",
		WouldMutate: false,
		APICalls:    []string{"ec2:DescribeInstances", "ec2:DescribeInstanceAttribute"},
	}
}

func (m *EC2UserDataExtractModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	instanceID := ctx.InputString("instance_id")
	maxInstances := ctx.InputInt("max_instances")
	if maxInstances <= 0 {
		maxInstances = 100
	}

	var instanceIDs []string
	if instanceID != "" {
		instanceIDs = []string{instanceID}
	} else {
		instances, err := m.factory.ListEC2Instances(bgCtx, creds)
		if err != nil {
			return sdk.ErrResult(fmt.Errorf("listing instances: %w", err))
		}
		for _, inst := range instances {
			instanceIDs = append(instanceIDs, inst.InstanceID)
		}
		if len(instanceIDs) > maxInstances {
			instanceIDs = instanceIDs[:maxInstances]
		}
	}

	prog.Total(len(instanceIDs))

	var results []map[string]any
	withUserData := 0
	var credIndicators []string

	for i, id := range instanceIDs {
		prog.Update(i+1, "Extracting userData: "+id)

		encoded, err := m.factory.GetInstanceUserData(bgCtx, creds, id)
		if err != nil {
			results = append(results, map[string]any{
				"instance_id": id,
				"has_userdata": false,
				"error":       err.Error(),
			})
			continue
		}

		if encoded == "" {
			results = append(results, map[string]any{
				"instance_id": id,
				"has_userdata": false,
			})
			continue
		}

		// Decode base64 user data
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// Try raw content if base64 fails
			decoded = []byte(encoded)
		}

		content := string(decoded)
		withUserData++

		entry := map[string]any{
			"instance_id":  id,
			"has_userdata": true,
			"size_bytes":   len(content),
			"preview":      truncateSecret(content, 500),
		}

		// Scan for credential indicators
		indicators := scanForCredentials(content)
		if len(indicators) > 0 {
			entry["credential_indicators"] = indicators
			credIndicators = append(credIndicators, fmt.Sprintf("%s: %s", id, strings.Join(indicators, ", ")))
		}

		results = append(results, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"instances_checked":       len(instanceIDs),
			"instances_with_userdata": withUserData,
			"results":                 results,
			"credential_indicators":   credIndicators,
		},
	}
}

func (m *EC2UserDataExtractModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// scanForCredentials checks user data content for common credential patterns.
func scanForCredentials(content string) []string {
	lower := strings.ToLower(content)
	var indicators []string

	patterns := map[string]string{
		"aws_access_key_id":     "AWS access key reference",
		"aws_secret_access_key": "AWS secret key reference",
		"password":              "Password reference",
		"passwd":                "Password reference",
		"secret":                "Secret reference",
		"api_key":               "API key reference",
		"apikey":                "API key reference",
		"token":                 "Token reference",
		"database_url":          "Database URL",
		"db_password":           "Database password",
		"private_key":           "Private key reference",
		"-----begin":            "PEM-encoded key/certificate",
	}

	seen := make(map[string]bool)
	for pattern, label := range patterns {
		if strings.Contains(lower, pattern) && !seen[label] {
			indicators = append(indicators, label)
			seen[label] = true
		}
	}

	// Check for actual AWS access keys
	if strings.Contains(content, "AKIA") {
		indicators = append(indicators, "AWS access key literal (AKIA...)")
	}

	return indicators
}
