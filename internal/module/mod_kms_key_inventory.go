package module

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// KMSKeyInventoryModule enumerates KMS keys with their metadata, rotation
// status, and key policies.
type KMSKeyInventoryModule struct {
	factory *aws.ClientFactory
}

func (m *KMSKeyInventoryModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.kms.key-inventory",
		Name:        "KMS Key Inventory",
		Version:     "1.0.0",
		Description: "Enumerates all KMS keys with their metadata including key state, rotation status, key manager (AWS vs customer), and aliases. Identifies keys with potential security concerns.",
		Services:    []string{"kms"},
		RequiredActions: []string{
			"kms:ListKeys",
			"kms:DescribeKey",
			"kms:ListAliases",
			"kms:GetKeyRotationStatus",
		},
		RequiredResources: []string{"arn:aws:kms:*:*:key/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "check_rotation", Type: "bool", Default: true, Description: "Check key rotation status"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "key_count", Type: "int", Description: "Total keys found"},
			{Name: "customer_managed", Type: "int", Description: "Customer-managed keys"},
			{Name: "keys_without_rotation", Type: "[]string", Description: "Customer-managed keys without rotation"},
			{Name: "disabled_keys", Type: "[]string", Description: "Keys in disabled state"},
			{Name: "key_details", Type: "[]map", Description: "Full key details"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1552/",
		},
		Author: "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "KMS", SortOrder: 1},
	}
}

func (m *KMSKeyInventoryModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"kms:ListKeys",
			"kms:DescribeKey (per key)",
			"kms:ListAliases",
			"kms:GetKeyRotationStatus (per customer-managed key)",
		},
		Confidence: 1.0,
	}
}

func (m *KMSKeyInventoryModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call kms:ListKeys, kms:DescribeKey per key, and kms:GetKeyRotationStatus for customer-managed keys.",
		WouldMutate: false,
		APICalls:    []string{"kms:ListKeys", "kms:DescribeKey", "kms:ListAliases", "kms:GetKeyRotationStatus"},
	}
}

func (m *KMSKeyInventoryModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	// List keys
	keys, err := m.factory.ListKMSKeys(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing KMS keys: %w", err))
	}

	prog.Total(len(keys))

	client := m.factory.KMSClient(creds)
	checkRotation := ctx.InputBool("check_rotation")

	var keyDetails []map[string]any
	var keysWithoutRotation []string
	var disabledKeys []string
	customerManaged := 0

	for i, key := range keys {
		prog.Update(i+1, "Checking: "+key.KeyID)

		detail := map[string]any{
			"key_id":  key.KeyID,
			"key_arn": key.KeyARN,
			"aliases": key.Aliases,
		}

		// Describe key for metadata
		m.factory.WaitForService("kms")
		descOut, err := client.DescribeKey(bgCtx, &kms.DescribeKeyInput{
			KeyId: awssdk.String(key.KeyID),
		})
		if err != nil {
			detail["describe_error"] = err.Error()
			keyDetails = append(keyDetails, detail)
			continue
		}

		km := descOut.KeyMetadata
		detail["key_state"] = string(km.KeyState)
		detail["key_usage"] = string(km.KeyUsage)
		detail["key_manager"] = string(km.KeyManager)
		detail["creation_date"] = km.CreationDate.Format("2006-01-02")
		detail["description"] = awssdk.ToString(km.Description)

		if km.KeyManager == kmstypes.KeyManagerTypeCustomer {
			customerManaged++
			detail["is_customer_managed"] = true

			// Check rotation status for customer-managed keys
			if checkRotation {
				m.factory.WaitForService("kms")
				rotOut, err := client.GetKeyRotationStatus(bgCtx, &kms.GetKeyRotationStatusInput{
					KeyId: awssdk.String(key.KeyID),
				})
				if err == nil {
					detail["rotation_enabled"] = rotOut.KeyRotationEnabled
					if !rotOut.KeyRotationEnabled {
						aliasLabel := key.KeyID
						if len(key.Aliases) > 0 {
							aliasLabel = key.Aliases[0]
						}
						keysWithoutRotation = append(keysWithoutRotation, aliasLabel)
					}
				}
			}
		}

		if km.KeyState == kmstypes.KeyStateDisabled {
			aliasLabel := key.KeyID
			if len(key.Aliases) > 0 {
				aliasLabel = key.Aliases[0]
			}
			disabledKeys = append(disabledKeys, aliasLabel)
		}

		keyDetails = append(keyDetails, detail)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"key_count":             len(keys),
			"customer_managed":      customerManaged,
			"keys_without_rotation": keysWithoutRotation,
			"disabled_keys":         disabledKeys,
			"key_details":           keyDetails,
		},
	}
}

func (m *KMSKeyInventoryModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
