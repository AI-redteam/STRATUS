package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// StopTrailModule disables logging on a CloudTrail trail.
// This is a destructive-risk module used for defense evasion testing (T1562.008).
type StopTrailModule struct {
	factory *aws.ClientFactory
}

func (m *StopTrailModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.cloudtrail.stop-trail",
		Name:        "Stop CloudTrail Logging",
		Version:     "1.0.0",
		Description: "Stops logging on a specified CloudTrail trail. Used for defense evasion testing. This is a destructive operation that disables audit logging in the target account.",
		Services:    []string{"cloudtrail"},
		RequiredActions: []string{
			"cloudtrail:StopLogging",
		},
		RequiredResources: []string{"arn:aws:cloudtrail:*:*:trail/*"},
		RiskClass:         sdk.RiskDestructive,
		Inputs: []sdk.InputSpec{
			{Name: "trail_name", Type: "string", Description: "Name or ARN of the CloudTrail trail to stop", Required: true},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "trail_name", Type: "string", Description: "The trail that was stopped"},
			{Name: "stopped", Type: "bool", Description: "Whether logging was successfully stopped"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1562/008/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "CloudTrail", SortOrder: 2},
	}
}

func (m *StopTrailModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	trailName := ctx.InputString("trail_name")
	if trailName == "" {
		return sdk.PreflightResult{
			MissingPermissions: []string{"(trail_name input is required)"},
			PlannedAPICalls:    []string{"cloudtrail:StopLogging"},
			Confidence:         0.0,
		}
	}
	return sdk.PreflightResult{
		PlannedAPICalls: []string{"cloudtrail:StopLogging"},
		Confidence:      1.0,
		Warnings:        []string{"DESTRUCTIVE: This will disable CloudTrail logging"},
	}
}

func (m *StopTrailModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	trailName := ctx.InputString("trail_name")
	return sdk.DryRunResult{
		Description: fmt.Sprintf("Would call cloudtrail:StopLogging on trail %q. This DISABLES audit logging.", trailName),
		WouldMutate: true,
		APICalls:    []string{"cloudtrail:StopLogging"},
	}
}

func (m *StopTrailModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	trailName := ctx.InputString("trail_name")
	if trailName == "" {
		return sdk.ErrResult(fmt.Errorf("trail_name input is required"))
	}

	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	prog.Total(1)
	prog.Update(1, "Stopping trail: "+trailName)

	err := m.factory.StopTrail(bgCtx, creds, trailName)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("stopping trail: %w", err))
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"trail_name": trailName,
			"stopped":    true,
		},
	}
}

func (m *StopTrailModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	// Destructive ops are not idempotent — return prior outputs instead of re-executing
	return sdk.RunResult{Outputs: prior.Outputs}
}
