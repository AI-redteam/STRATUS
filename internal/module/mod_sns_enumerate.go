package module

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// SNSEnumerateModule lists SNS topics and their access policies,
// identifying topics with overly permissive policies that could allow
// subscription hijacking or message injection.
type SNSEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *SNSEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.sns.enumerate-topics",
		Name:        "Enumerate SNS Topics",
		Version:     "1.0.0",
		Description: "Lists all SNS topics in the target region with access policies. Identifies topics with overly permissive policies that could allow unauthorized subscription or message publishing by cross-account or public principals.",
		Services:    []string{"sns"},
		RequiredActions: []string{
			"sns:ListTopics",
			"sns:GetTopicAttributes",
		},
		RequiredResources: []string{"arn:aws:sns:*:*:*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_topics", Type: "int", Default: 200, Description: "Maximum topics to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "topic_count", Type: "int", Description: "Total topics found"},
			{Name: "topics", Type: "[]map", Description: "Topic details with policy analysis"},
			{Name: "public_topics", Type: "[]string", Description: "Topics with public access in policy"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "SNS", SortOrder: 1},
	}
}

func (m *SNSEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"sns:ListTopics (paginated)",
			"sns:GetTopicAttributes (per topic)",
		},
		Confidence: 1.0,
	}
}

func (m *SNSEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call sns:ListTopics then sns:GetTopicAttributes for each topic to analyze access policies.",
		WouldMutate: false,
		APICalls:    []string{"sns:ListTopics", "sns:GetTopicAttributes"},
	}
}

func (m *SNSEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	topics, err := m.factory.ListSNSTopics(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing SNS topics: %w", err))
	}

	maxTopics := ctx.InputInt("max_topics")
	if maxTopics <= 0 {
		maxTopics = 200
	}
	if len(topics) > maxTopics {
		topics = topics[:maxTopics]
	}

	prog.Total(len(topics))

	var results []map[string]any
	var publicTopics []string

	for i, topic := range topics {
		prog.Update(i+1, "Analyzing: "+topic.TopicARN)

		entry := map[string]any{
			"topic_arn":    topic.TopicARN,
			"display_name": topic.DisplayName,
			"subscriptions": topic.Subscriptions,
		}

		// Analyze topic policy for public access
		if topic.Policy != "" {
			isPublic, reason := analyzeSNSPolicy(topic.Policy)
			entry["has_policy"] = true
			entry["public_access"] = isPublic
			if isPublic {
				entry["public_reason"] = reason
				publicTopics = append(publicTopics, topic.TopicARN)
			}
		}

		results = append(results, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"topic_count":   len(topics),
			"topics":        results,
			"public_topics": publicTopics,
		},
	}
}

func (m *SNSEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// analyzeSNSPolicy checks if an SNS topic policy grants public access.
func analyzeSNSPolicy(policyJSON string) (isPublic bool, reason string) {
	var doc struct {
		Statement []struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Action    interface{} `json:"Action"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return false, ""
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		if isPublicPrincipal(stmt.Principal) {
			actions := flattenActions(stmt.Action)
			return true, fmt.Sprintf("public principal with actions: %v", actions)
		}
	}

	return false, ""
}
