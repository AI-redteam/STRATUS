package module

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CloudTrailStatusModule enumerates CloudTrail trails and checks their
// logging status, configuration, and potential gaps.
type CloudTrailStatusModule struct {
	factory *aws.ClientFactory
}

func (m *CloudTrailStatusModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.cloudtrail.status",
		Name:        "CloudTrail Status Check",
		Version:     "1.0.0",
		Description: "Enumerates all CloudTrail trails, checks logging status, multi-region configuration, log file validation, and S3 bucket targets. Identifies trails that are not logging or have gaps in coverage.",
		Services:    []string{"cloudtrail"},
		RequiredActions: []string{
			"cloudtrail:DescribeTrails",
			"cloudtrail:GetTrailStatus",
		},
		RequiredResources: []string{"arn:aws:cloudtrail:*:*:trail/*"},
		RiskClass:         sdk.RiskReadOnly,
		Outputs: []sdk.OutputSpec{
			{Name: "trail_count", Type: "int", Description: "Total trails found"},
			{Name: "trails_logging", Type: "int", Description: "Trails currently logging"},
			{Name: "trails_not_logging", Type: "[]string", Description: "Trails not currently logging"},
			{Name: "multi_region_trails", Type: "[]string", Description: "Trails with multi-region enabled"},
			{Name: "trail_details", Type: "[]map", Description: "Full trail details"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1562/008/",
		},
		Author: "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "CloudTrail", SortOrder: 1},
	}
}

func (m *CloudTrailStatusModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus (per trail)"},
		Confidence:      1.0,
	}
}

func (m *CloudTrailStatusModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call cloudtrail:DescribeTrails to list all trails, then cloudtrail:GetTrailStatus for each to check logging state.",
		WouldMutate: false,
		APICalls:    []string{"cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"},
	}
}

func (m *CloudTrailStatusModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	client := m.factory.CloudTrailClient(creds)
	m.factory.WaitForService("cloudtrail")

	descOut, err := client.DescribeTrails(bgCtx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("describing trails: %w", err))
	}

	trails := descOut.TrailList
	prog.Total(len(trails))

	var trailsNotLogging []string
	var multiRegionTrails []string
	trailsLogging := 0
	var trailDetails []map[string]any

	for i, trail := range trails {
		name := awssdk.ToString(trail.TrailARN)
		trailName := awssdk.ToString(trail.Name)
		prog.Update(i+1, "Checking: "+trailName)

		detail := map[string]any{
			"name":                trailName,
			"arn":                 name,
			"s3_bucket":          awssdk.ToString(trail.S3BucketName),
			"s3_prefix":          awssdk.ToString(trail.S3KeyPrefix),
			"is_multi_region":    trail.IsMultiRegionTrail != nil && *trail.IsMultiRegionTrail,
			"log_file_validation": trail.LogFileValidationEnabled != nil && *trail.LogFileValidationEnabled,
			"is_organization":    trail.IsOrganizationTrail,
			"home_region":        awssdk.ToString(trail.HomeRegion),
		}

		if trail.IsMultiRegionTrail != nil && *trail.IsMultiRegionTrail {
			multiRegionTrails = append(multiRegionTrails, trailName)
		}

		// Check logging status
		m.factory.WaitForService("cloudtrail")
		statusOut, err := client.GetTrailStatus(bgCtx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err != nil {
			detail["logging_status"] = "error"
			detail["logging_error"] = err.Error()
		} else {
			isLogging := statusOut.IsLogging != nil && *statusOut.IsLogging
			detail["is_logging"] = isLogging

			if statusOut.LatestDeliveryTime != nil {
				detail["latest_delivery"] = statusOut.LatestDeliveryTime.Format("2006-01-02 15:04:05")
			}
			if statusOut.LatestDeliveryError != nil {
				detail["delivery_error"] = awssdk.ToString(statusOut.LatestDeliveryError)
			}

			if isLogging {
				trailsLogging++
			} else {
				trailsNotLogging = append(trailsNotLogging, trailName)
			}
		}

		trailDetails = append(trailDetails, detail)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"trail_count":        len(trails),
			"trails_logging":     trailsLogging,
			"trails_not_logging": trailsNotLogging,
			"multi_region_trails": multiRegionTrails,
			"trail_details":      trailDetails,
		},
	}
}

func (m *CloudTrailStatusModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
