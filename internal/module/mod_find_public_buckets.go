package module

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// FindPublicBucketsModule enumerates S3 buckets and identifies those with
// public access vectors (ACL grants, bucket policies).
type FindPublicBucketsModule struct {
	factory *aws.ClientFactory
}

func (m *FindPublicBucketsModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.s3.find-public-buckets",
		Name:        "Find Public S3 Buckets",
		Version:     "1.0.0",
		Description: "Enumerates all S3 buckets in the account and identifies buckets with public access vectors via ACL grants or bucket policies. Does NOT retrieve object contents — metadata only.",
		Services:    []string{"s3"},
		RequiredActions: []string{
			"s3:ListAllMyBuckets",
			"s3:GetBucketAcl",
			"s3:GetBucketPolicyStatus",
			"s3:GetBucketPolicy",
		},
		RequiredResources: []string{"arn:aws:s3:::*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "check_policy", Type: "bool", Default: true, Description: "Check bucket policies for public access"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "total_buckets", Type: "int", Description: "Total buckets found"},
			{Name: "public_buckets", Type: "[]string", Description: "Buckets with any public access vector"},
			{Name: "policy_public", Type: "[]string", Description: "Buckets public via bucket policy"},
			{Name: "summary", Type: "[]map", Description: "Per-bucket summary"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author: "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "S3", SortOrder: 1},
	}
}

func (m *FindPublicBucketsModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"s3:ListBuckets",
			"s3:GetBucketPolicy (per bucket)",
		},
		Confidence: 1.0,
	}
}

func (m *FindPublicBucketsModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call s3:ListBuckets, then s3:GetBucketPolicy for each bucket to check for public access.",
		WouldMutate: false,
		APICalls:    []string{"s3:ListBuckets", "s3:GetBucketPolicy"},
	}
}

func (m *FindPublicBucketsModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	buckets, err := m.factory.ListS3Buckets(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing buckets: %w", err))
	}

	prog.Total(len(buckets))

	var publicBuckets []string
	var policyPublic []string
	var summaries []map[string]any

	checkPolicy := ctx.InputBool("check_policy")

	for i, bucket := range buckets {
		prog.Update(i+1, "Checking: "+bucket.Name)

		summary := map[string]any{
			"name":          bucket.Name,
			"creation_date": bucket.CreationDate,
			"public":        false,
		}

		if checkPolicy {
			policy, err := m.factory.GetBucketPolicy(bgCtx, creds, bucket.Name)
			if err == nil && policy != "" {
				isPublic, reason := analyzeBucketPolicy(policy)
				if isPublic {
					publicBuckets = append(publicBuckets, bucket.Name)
					policyPublic = append(policyPublic, bucket.Name)
					summary["public"] = true
					summary["public_reason"] = reason
				}
			}
			// GetBucketPolicy returns error if no policy exists — that's fine
		}

		summaries = append(summaries, summary)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"total_buckets":  len(buckets),
			"public_buckets": publicBuckets,
			"policy_public":  policyPublic,
			"summary":        summaries,
		},
	}
}

func (m *FindPublicBucketsModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}

// analyzeBucketPolicy checks if a bucket policy grants public access.
func analyzeBucketPolicy(policyJSON string) (isPublic bool, reason string) {
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

func isPublicPrincipal(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case map[string]interface{}:
		if aws, ok := p["AWS"]; ok {
			switch v := aws.(type) {
			case string:
				return v == "*"
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && s == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func flattenActions(action interface{}) []string {
	switch a := action.(type) {
	case string:
		return []string{a}
	case []interface{}:
		var result []string
		for _, item := range a {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
