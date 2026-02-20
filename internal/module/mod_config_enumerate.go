package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// ConfigEnumerateModule discovers AWS Config recorders, delivery channels,
// and compliance rules. Identifies detection gaps (stopped recorders),
// delivery targets (S3 buckets, SNS topics for tampering), and non-compliant
// resources that represent exploitable weaknesses.
type ConfigEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *ConfigEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.config.enumerate",
		Name:        "Enumerate AWS Config",
		Version:     "1.0.0",
		Description: "Enumerates AWS Config recorders, delivery channels, and compliance rules. Identifies detection gaps (stopped recorders, limited scope), delivery targets (S3 buckets and SNS topics that could be tampered with), and non-compliant resources. Non-compliant Config rules reveal misconfigurations an attacker can exploit. Stopped or missing recorders indicate blind spots in the defender's visibility.",
		Services:    []string{"config"},
		RequiredActions: []string{
			"config:DescribeConfigurationRecorders",
			"config:DescribeConfigurationRecorderStatus",
			"config:DescribeDeliveryChannels",
			"config:DescribeConfigRules",
			"config:DescribeComplianceByConfigRule",
		},
		RequiredResources: []string{"*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "check_compliance", Type: "bool", Default: true, Description: "Also check rule compliance status"},
			{Name: "max_rules", Type: "int", Default: 200, Description: "Maximum config rules to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "recorders", Type: "[]map", Description: "Config recorder details with status"},
			{Name: "delivery_channels", Type: "[]map", Description: "Delivery channel details (S3 buckets, SNS topics)"},
			{Name: "rules", Type: "[]map", Description: "Config rule details"},
			{Name: "rule_count", Type: "int", Description: "Total config rules"},
			{Name: "compliance", Type: "[]map", Description: "Per-rule compliance summary"},
			{Name: "findings", Type: "[]map", Description: "Security findings"},
			{Name: "finding_count", Type: "int", Description: "Total findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1562.008/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Config", SortOrder: 1},
	}
}

func (m *ConfigEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{
		"config:DescribeConfigurationRecorders",
		"config:DescribeConfigurationRecorderStatus",
		"config:DescribeDeliveryChannels",
		"config:DescribeConfigRules",
	}
	if ctx.InputBool("check_compliance") {
		calls = append(calls, "config:DescribeComplianceByConfigRule")
	}
	return sdk.PreflightResult{
		PlannedAPICalls: calls,
		Confidence:      1.0,
	}
}

func (m *ConfigEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	desc := "Would enumerate AWS Config recorders, delivery channels, and rules."
	if ctx.InputBool("check_compliance") {
		desc += " Would also check compliance status for each rule."
	}
	return sdk.DryRunResult{
		Description: desc,
		WouldMutate: false,
		APICalls: []string{
			"config:DescribeConfigurationRecorders",
			"config:DescribeConfigurationRecorderStatus",
			"config:DescribeDeliveryChannels",
			"config:DescribeConfigRules",
			"config:DescribeComplianceByConfigRule",
		},
	}
}

func (m *ConfigEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	findings := make([]map[string]any, 0)
	steps := 3
	if ctx.InputBool("check_compliance") {
		steps = 4
	}
	prog.Total(steps)

	// --- Step 1: Config Recorders ---
	prog.Update(1, "Checking Config recorders")

	recorders, err := m.factory.ListConfigRecorders(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing Config recorders: %w", err))
	}

	recorderResults := make([]map[string]any, 0)
	if len(recorders) == 0 {
		findings = append(findings, map[string]any{
			"resource": "config_recorders",
			"finding":  "NoRecorders",
			"severity": "critical",
			"detail":   "No AWS Config recorders found in this region. Resource changes are not being tracked. This is a complete detection blind spot.",
		})
	}

	for _, rec := range recorders {
		entry := map[string]any{
			"name":                    rec.Name,
			"role_arn":                rec.RoleARN,
			"all_supported":           rec.AllSupported,
			"include_global":          rec.IncludeGlobal,
			"recording":              rec.Recording,
			"last_status":            rec.LastStatus,
			"last_start_time":        rec.LastStartTime,
			"last_stop_time":         rec.LastStopTime,
			"last_error_code":        rec.LastErrorCode,
			"last_error_message":     rec.LastErrorMsg,
		}
		recorderResults = append(recorderResults, entry)

		if !rec.Recording {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("recorder/%s", rec.Name),
				"finding":  "RecorderStopped",
				"severity": "critical",
				"detail":   fmt.Sprintf("Config recorder %s is not recording. Resource changes are not being captured. This could be intentional attacker action (T1562.008) or misconfiguration.", rec.Name),
			})
		}

		if !rec.AllSupported {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("recorder/%s", rec.Name),
				"finding":  "LimitedScope",
				"severity": "medium",
				"detail":   fmt.Sprintf("Config recorder %s does not record all supported resource types. Some resource changes may not be captured.", rec.Name),
			})
		}

		if !rec.IncludeGlobal {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("recorder/%s", rec.Name),
				"finding":  "NoGlobalResources",
				"severity": "medium",
				"detail":   fmt.Sprintf("Config recorder %s does not include global resources (IAM, CloudFront, etc.). IAM changes may not be tracked.", rec.Name),
			})
		}

		if rec.LastErrorCode != "" {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("recorder/%s", rec.Name),
				"finding":  "RecorderError",
				"severity": "high",
				"detail":   fmt.Sprintf("Config recorder %s has errors: %s - %s. This may indicate tampered IAM permissions or S3 bucket issues.", rec.Name, rec.LastErrorCode, rec.LastErrorMsg),
			})
		}
	}

	// --- Step 2: Delivery Channels ---
	prog.Update(2, "Checking delivery channels")

	channels, err := m.factory.ListConfigDeliveryChannels(bgCtx, creds)
	channelResults := make([]map[string]any, 0)
	if err != nil {
		findings = append(findings, map[string]any{
			"resource": "delivery_channels",
			"finding":  "ListFailed",
			"severity": "info",
			"detail":   fmt.Sprintf("could not list delivery channels: %v", err),
		})
	} else {
		if len(channels) == 0 && len(recorders) > 0 {
			findings = append(findings, map[string]any{
				"resource": "delivery_channels",
				"finding":  "NoDeliveryChannels",
				"severity": "high",
				"detail":   "Config recorders exist but no delivery channels configured. Configuration data has nowhere to go.",
			})
		}

		for _, ch := range channels {
			entry := map[string]any{
				"name":               ch.Name,
				"s3_bucket_name":     ch.S3BucketName,
				"s3_key_prefix":      ch.S3KeyPrefix,
				"sns_topic_arn":      ch.SNSTopicARN,
				"delivery_frequency": ch.DeliveryFrequency,
			}
			channelResults = append(channelResults, entry)

			// Flag delivery targets as potential tampering targets
			if ch.S3BucketName != "" {
				findings = append(findings, map[string]any{
					"resource": fmt.Sprintf("channel/%s", ch.Name),
					"finding":  "DeliveryBucket",
					"severity": "info",
					"detail":   fmt.Sprintf("Config data delivered to S3 bucket: %s. If bucket policy allows, an attacker could tamper with or delete configuration history.", ch.S3BucketName),
				})
			}

			if ch.SNSTopicARN != "" {
				findings = append(findings, map[string]any{
					"resource": fmt.Sprintf("channel/%s", ch.Name),
					"finding":  "DeliverySNSTopic",
					"severity": "info",
					"detail":   fmt.Sprintf("Config streams delivered to SNS topic: %s. If subscriptions can be added, an attacker could monitor all resource changes in real-time.", ch.SNSTopicARN),
				})
			}
		}
	}

	// --- Step 3: Config Rules ---
	prog.Update(3, "Listing Config rules")

	maxRules := ctx.InputInt("max_rules")
	if maxRules <= 0 {
		maxRules = 200
	}

	rules, err := m.factory.ListConfigRules(bgCtx, creds)
	ruleResults := make([]map[string]any, 0)
	if err != nil {
		findings = append(findings, map[string]any{
			"resource": "config_rules",
			"finding":  "ListFailed",
			"severity": "info",
			"detail":   fmt.Sprintf("could not list config rules: %v", err),
		})
	} else {
		if len(rules) == 0 {
			findings = append(findings, map[string]any{
				"resource": "config_rules",
				"finding":  "NoRules",
				"severity": "medium",
				"detail":   "No Config rules defined. No compliance checks are being enforced.",
			})
		}

		customRuleCount := 0
		for i, rule := range rules {
			if i >= maxRules {
				break
			}
			entry := map[string]any{
				"rule_name":     rule.RuleName,
				"rule_arn":      rule.RuleARN,
				"rule_id":       rule.RuleID,
				"source":        rule.Source,
				"source_id":     rule.SourceID,
				"state":         rule.State,
				"max_frequency": rule.MaxFrequency,
			}
			if rule.InputParams != "" {
				entry["input_parameters"] = rule.InputParams
			}
			ruleResults = append(ruleResults, entry)

			if rule.Source == "CUSTOM_LAMBDA" {
				customRuleCount++
			}
		}

		if customRuleCount > 0 {
			findings = append(findings, map[string]any{
				"resource": "config_rules",
				"finding":  "CustomLambdaRules",
				"severity": "info",
				"detail":   fmt.Sprintf("Found %d custom Lambda-backed Config rules. If the backing Lambda functions can be modified, compliance checks can be disabled or used for code execution.", customRuleCount),
			})
		}
	}

	// --- Step 4: Compliance ---
	complianceResults := make([]map[string]any, 0)
	if ctx.InputBool("check_compliance") {
		prog.Update(4, "Checking rule compliance")

		compliance, err := m.factory.GetConfigRuleCompliance(bgCtx, creds)
		if err == nil {
			nonCompliantCount := 0
			for _, c := range compliance {
				complianceResults = append(complianceResults, map[string]any{
					"rule_name":     c.RuleName,
					"compliant":     c.Compliant,
					"non_compliant": c.NonCompliant,
				})
				if c.NonCompliant > 0 {
					nonCompliantCount++
				}
			}
			if nonCompliantCount > 0 {
				findings = append(findings, map[string]any{
					"resource": "compliance",
					"finding":  "NonCompliantRules",
					"severity": "medium",
					"detail":   fmt.Sprintf("%d Config rules have non-compliant resources. These misconfigurations may be exploitable.", nonCompliantCount),
				})
			}
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"recorders":         recorderResults,
			"delivery_channels": channelResults,
			"rules":             ruleResults,
			"rule_count":        len(ruleResults),
			"compliance":        complianceResults,
			"findings":          findings,
			"finding_count":     len(findings),
		},
	}
}

func (m *ConfigEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
