package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// DynamoDBEnumerateModule lists DynamoDB tables with metadata including
// item count, size, encryption status, and table class.
type DynamoDBEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *DynamoDBEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.dynamodb.enumerate-tables",
		Name:        "Enumerate DynamoDB Tables",
		Version:     "1.0.0",
		Description: "Lists all DynamoDB tables in the target region with detailed metadata: item count, size, encryption status, and table class. Identifies tables containing significant data volumes and those without customer-managed encryption.",
		Services:    []string{"dynamodb"},
		RequiredActions: []string{
			"dynamodb:ListTables",
			"dynamodb:DescribeTable",
		},
		RequiredResources: []string{"arn:aws:dynamodb:*:*:table/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_tables", Type: "int", Default: 200, Description: "Maximum tables to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "table_count", Type: "int", Description: "Total tables found"},
			{Name: "tables", Type: "[]map", Description: "Table details"},
			{Name: "total_items", Type: "int", Description: "Total items across all tables"},
			{Name: "total_size_bytes", Type: "int", Description: "Total size across all tables"},
			{Name: "unencrypted_tables", Type: "[]string", Description: "Tables without customer-managed encryption"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1530/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "DynamoDB", SortOrder: 1},
	}
}

func (m *DynamoDBEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"dynamodb:ListTables (paginated)",
			"dynamodb:DescribeTable (per table)",
		},
		Confidence: 1.0,
	}
}

func (m *DynamoDBEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would call dynamodb:ListTables then dynamodb:DescribeTable for each table to collect metadata.",
		WouldMutate: false,
		APICalls:    []string{"dynamodb:ListTables", "dynamodb:DescribeTable"},
	}
}

func (m *DynamoDBEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	tables, err := m.factory.ListDynamoDBTables(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing DynamoDB tables: %w", err))
	}

	maxTables := ctx.InputInt("max_tables")
	if maxTables <= 0 {
		maxTables = 200
	}
	if len(tables) > maxTables {
		tables = tables[:maxTables]
	}

	prog.Total(len(tables))

	var details []map[string]any
	var totalItems int64
	var totalSize int64
	var unencryptedTables []string

	for i, table := range tables {
		prog.Update(i+1, "Processing: "+table.TableName)

		entry := map[string]any{
			"table_name":  table.TableName,
			"table_arn":   table.TableARN,
			"status":      table.Status,
			"item_count":  table.ItemCount,
			"size_bytes":  table.SizeBytes,
			"table_class": table.TableClass,
			"encrypted":   table.Encrypted,
		}

		totalItems += table.ItemCount
		totalSize += table.SizeBytes

		if !table.Encrypted {
			unencryptedTables = append(unencryptedTables, table.TableName)
		}

		// Flag large tables as higher exfiltration value
		if table.SizeBytes > 100*1024*1024 { // > 100MB
			entry["data_value"] = "high"
		} else if table.ItemCount > 10000 {
			entry["data_value"] = "medium"
		}

		details = append(details, entry)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"table_count":        len(tables),
			"tables":             details,
			"total_items":        totalItems,
			"total_size_bytes":   totalSize,
			"unencrypted_tables": unencryptedTables,
		},
	}
}

func (m *DynamoDBEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
