package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// S3ExfilCheckModule tests S3 bucket data access by listing objects,
// checking encryption, and assessing exfiltration risk.
type S3ExfilCheckModule struct {
	factory *aws.ClientFactory
}

func (m *S3ExfilCheckModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.s3.exfil-check",
		Name:        "S3 Exfiltration Check",
		Version:     "1.0.0",
		Description: "Tests S3 bucket data access by listing objects, checking encryption configuration, and identifying buckets where data exfiltration would be possible. Assesses bucket-level controls without downloading actual data.",
		Services:    []string{"s3"},
		RequiredActions: []string{
			"s3:ListAllMyBuckets",
			"s3:ListBucket",
			"s3:GetEncryptionConfiguration",
			"s3:GetBucketPolicy",
		},
		RequiredResources: []string{"arn:aws:s3:::*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "target_bucket", Type: "string", Description: "Specific bucket to check (leave empty for all)"},
			{Name: "max_objects", Type: "int", Default: 20, Description: "Maximum objects to list per bucket for sampling"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "buckets_checked", Type: "int", Description: "Total buckets checked"},
			{Name: "accessible_buckets", Type: "[]string", Description: "Buckets where objects are listable"},
			{Name: "unencrypted_buckets", Type: "[]string", Description: "Buckets without server-side encryption"},
			{Name: "summary", Type: "[]map", Description: "Per-bucket exfiltration risk summary"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "S3", SortOrder: 2},
	}
}

func (m *S3ExfilCheckModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"s3:ListBuckets",
			"s3:ListObjectsV2 (per bucket)",
			"s3:GetBucketEncryption (per bucket)",
			"s3:GetBucketPolicy (per bucket)",
		},
		Confidence: 1.0,
	}
}

func (m *S3ExfilCheckModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	target := ctx.InputString("target_bucket")
	if target != "" {
		return sdk.DryRunResult{
			Description: fmt.Sprintf("Would check bucket %q for data access: list objects, check encryption, and analyze bucket policy.", target),
			WouldMutate: false,
			APICalls:    []string{"s3:ListObjectsV2", "s3:GetBucketEncryption", "s3:GetBucketPolicy"},
		}
	}
	return sdk.DryRunResult{
		Description: "Would enumerate all S3 buckets and check each for data access controls, encryption, and exfiltration risk.",
		WouldMutate: false,
		APICalls:    []string{"s3:ListBuckets", "s3:ListObjectsV2", "s3:GetBucketEncryption", "s3:GetBucketPolicy"},
	}
}

func (m *S3ExfilCheckModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	targetBucket := ctx.InputString("target_bucket")
	maxObjects := ctx.InputInt("max_objects")
	if maxObjects <= 0 {
		maxObjects = 20
	}

	var bucketNames []string
	if targetBucket != "" {
		bucketNames = []string{targetBucket}
	} else {
		buckets, err := m.factory.ListS3Buckets(bgCtx, creds)
		if err != nil {
			return sdk.ErrResult(fmt.Errorf("listing buckets: %w", err))
		}
		for _, b := range buckets {
			bucketNames = append(bucketNames, b.Name)
		}
	}

	prog.Total(len(bucketNames))

	var accessibleBuckets []string
	var unencryptedBuckets []string
	var summaries []map[string]any

	for i, bucket := range bucketNames {
		prog.Update(i+1, "Checking: "+bucket)

		summary := map[string]any{
			"bucket":     bucket,
			"accessible": false,
			"encrypted":  true,
			"risk_level": "low",
		}

		// Check if we can list objects
		objects, err := m.factory.ListS3Objects(bgCtx, creds, bucket, "", int32(maxObjects))
		if err == nil {
			summary["accessible"] = true
			summary["sample_object_count"] = len(objects)
			accessibleBuckets = append(accessibleBuckets, bucket)

			var totalSize int64
			for _, obj := range objects {
				totalSize += obj.Size
			}
			summary["sample_total_size_bytes"] = totalSize
		}

		// Check encryption
		encryption, err := m.factory.GetS3BucketEncryption(bgCtx, creds, bucket)
		if err != nil {
			summary["encrypted"] = false
			summary["encryption"] = "none_or_error"
			unencryptedBuckets = append(unencryptedBuckets, bucket)
		} else {
			summary["encryption"] = encryption
			if encryption == "none" {
				summary["encrypted"] = false
				unencryptedBuckets = append(unencryptedBuckets, bucket)
			}
		}

		// Check bucket policy for public access
		policy, err := m.factory.GetBucketPolicy(bgCtx, creds, bucket)
		if err == nil && policy != "" {
			isPublic, reason := analyzeBucketPolicy(policy)
			summary["has_policy"] = true
			summary["public_policy"] = isPublic
			if isPublic {
				summary["public_reason"] = reason
			}
		}

		// Assess risk level
		accessible := summary["accessible"].(bool)
		encrypted := summary["encrypted"].(bool)
		if accessible && !encrypted {
			summary["risk_level"] = "critical"
		} else if accessible {
			summary["risk_level"] = "medium"
		}

		summaries = append(summaries, summary)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"buckets_checked":     len(bucketNames),
			"accessible_buckets":  accessibleBuckets,
			"unencrypted_buckets": unencryptedBuckets,
			"summary":            summaries,
		},
	}
}

func (m *S3ExfilCheckModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
