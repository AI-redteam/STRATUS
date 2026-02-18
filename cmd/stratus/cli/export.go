package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stratus-framework/stratus/internal/graph"
)

// RegisterExportCommands adds evidence export commands.
func RegisterExportCommands(root *cobra.Command) {
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export workspace evidence bundle",
		Long: `Export a complete evidence bundle for the workspace. Includes identities,
sessions, graph data, module runs, and audit log. No secret material is included.

Formats:
  json      — Machine-readable JSON files (default)
  markdown  — Human-readable markdown report with embedded data`,
	}

	var (
		format string
		output string
	)

	exportCmd.Flags().StringVar(&format, "format", "json", "Export format (json, markdown)")
	exportCmd.Flags().StringVar(&output, "output", "", "Output directory (required)")

	exportCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if output == "" {
			return fmt.Errorf("--output is required")
		}
		if format != "json" && format != "markdown" {
			return fmt.Errorf("unsupported format: %s (use 'json' or 'markdown')", format)
		}

		engine, err := loadActiveEngine()
		if err != nil {
			return err
		}
		defer engine.Close()

		// Create export directory structure
		dirs := []string{
			output,
			filepath.Join(output, "identities"),
			filepath.Join(output, "sessions"),
			filepath.Join(output, "graph"),
			filepath.Join(output, "runs"),
			filepath.Join(output, "audit"),
		}
		for _, d := range dirs {
			if err := os.MkdirAll(d, 0755); err != nil {
				return fmt.Errorf("creating directory %s: %w", d, err)
			}
		}

		fmt.Printf("Exporting workspace: %s (%s)\n", engine.Workspace.Name, engine.Workspace.UUID[:8])
		fmt.Printf("  Format: %s\n", format)
		fmt.Printf("  Output: %s\n\n", output)

		wsUUID := engine.Workspace.UUID

		if format == "markdown" {
			return exportMarkdown(engine.MetadataDB, engine.AuditDB, wsUUID, engine.Workspace, output)
		}
		return exportJSON(engine.MetadataDB, engine.AuditDB, wsUUID, engine.Workspace, output)
	}

	root.AddCommand(exportCmd)
}

// exportJSON produces a machine-readable JSON evidence bundle.
func exportJSON(metaDB, auditDB *sql.DB, wsUUID string, ws interface{ /* Workspace fields */ }, output string) error {
	type workspace interface {
		GetName() string
	}
	// Export workspace metadata
	wsData, _ := json.MarshalIndent(map[string]any{
		"exported_at":  time.Now().UTC().Format(time.RFC3339),
		"workspace_id": wsUUID,
		"format":       "stratus_evidence_bundle_v1",
	}, "", "  ")
	os.WriteFile(filepath.Join(output, "manifest.json"), wsData, 0644)

	// Identities
	idCount := exportIdentitiesJSON(metaDB, wsUUID, output)

	// Sessions
	sessCount := exportSessionsJSON(metaDB, wsUUID, output)

	// Graph
	graphCount := exportGraphJSON(metaDB, wsUUID, output)

	// Module runs
	runCount := exportRunsJSON(metaDB, wsUUID, output)

	// Audit log
	auditCount := exportAuditJSON(auditDB, wsUUID, output)

	fmt.Printf("  Identities: %d\n", idCount)
	fmt.Printf("  Sessions:   %d\n", sessCount)
	fmt.Printf("  Graph:      %d nodes/edges\n", graphCount)
	fmt.Printf("  Runs:       %d\n", runCount)
	fmt.Printf("  Audit:      %d events\n", auditCount)
	fmt.Printf("\nEvidence bundle exported to: %s\n", output)
	return nil
}

func exportIdentitiesJSON(db *sql.DB, wsUUID, output string) int {
	rows, err := db.Query(
		`SELECT uuid, label, account_id, principal_arn, principal_type, source_type, acquired_at, tags, is_archived
		 FROM identities WHERE workspace_uuid = ?`, wsUUID)
	if err != nil {
		return 0
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var uuid, label, accountID, principalARN, principalType, sourceType, acquiredAt, tags string
		var isArchived int
		rows.Scan(&uuid, &label, &accountID, &principalARN, &principalType, &sourceType, &acquiredAt, &tags, &isArchived)
		data, _ := json.MarshalIndent(map[string]any{
			"uuid":           uuid,
			"label":          label,
			"account_id":     accountID,
			"principal_arn":  principalARN,
			"principal_type": principalType,
			"source_type":    sourceType,
			"acquired_at":    acquiredAt,
			"is_archived":    isArchived != 0,
		}, "", "  ")
		os.WriteFile(filepath.Join(output, "identities", uuid+".json"), data, 0644)
		count++
	}
	return count
}

func exportSessionsJSON(db *sql.DB, wsUUID, output string) int {
	rows, err := db.Query(
		`SELECT uuid, identity_uuid, aws_access_key_id, session_name, region, expiry,
		        health_status, created_at, chain_parent_session_uuid, refresh_method
		 FROM sessions WHERE workspace_uuid = ?`, wsUUID)
	if err != nil {
		return 0
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var uuid, identityUUID, accessKeyID, name, region, health, createdAt string
		var expiry, chainParent, refreshMethod sql.NullString
		rows.Scan(&uuid, &identityUUID, &accessKeyID, &name, &region, &expiry, &health, &createdAt, &chainParent, &refreshMethod)

		// Redact access key
		redactedKey := accessKeyID
		if len(redactedKey) > 8 {
			redactedKey = redactedKey[:4] + "..." + redactedKey[len(redactedKey)-4:]
		}

		entry := map[string]any{
			"uuid":            uuid,
			"identity_uuid":   identityUUID,
			"access_key_hint": redactedKey,
			"session_name":    name,
			"region":          region,
			"health_status":   health,
			"created_at":      createdAt,
		}
		if expiry.Valid {
			entry["expiry"] = expiry.String
		}
		if chainParent.Valid {
			entry["chain_parent"] = chainParent.String
		}
		if refreshMethod.Valid {
			entry["refresh_method"] = refreshMethod.String
		}

		data, _ := json.MarshalIndent(entry, "", "  ")
		os.WriteFile(filepath.Join(output, "sessions", uuid+".json"), data, 0644)
		count++
	}
	return count
}

func exportGraphJSON(db *sql.DB, wsUUID, output string) int {
	store := graph.NewStore(db, wsUUID)
	data, err := store.Snapshot()
	if err != nil {
		return 0
	}
	os.WriteFile(filepath.Join(output, "graph", "graph.json"), data, 0644)

	// Count nodes + edges
	var nodeCount, edgeCount int
	db.QueryRow("SELECT COUNT(*) FROM graph_nodes WHERE workspace_uuid = ?", wsUUID).Scan(&nodeCount)
	db.QueryRow("SELECT COUNT(*) FROM graph_edges WHERE workspace_uuid = ?", wsUUID).Scan(&edgeCount)
	return nodeCount + edgeCount
}

func exportRunsJSON(db *sql.DB, wsUUID, output string) int {
	rows, err := db.Query(
		`SELECT uuid, module_id, module_version, session_uuid, status, started_at, completed_at, inputs, outputs, error_detail
		 FROM module_runs WHERE workspace_uuid = ? ORDER BY started_at DESC`, wsUUID)
	if err != nil {
		return 0
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var uuid, moduleID, moduleVersion, sessionUUID, status, startedAt string
		var completedAt, inputs, outputs, errorDetail sql.NullString
		rows.Scan(&uuid, &moduleID, &moduleVersion, &sessionUUID, &status, &startedAt, &completedAt, &inputs, &outputs, &errorDetail)

		entry := map[string]any{
			"uuid":           uuid,
			"module_id":      moduleID,
			"module_version": moduleVersion,
			"session_uuid":   sessionUUID,
			"status":         status,
			"started_at":     startedAt,
		}
		if completedAt.Valid {
			entry["completed_at"] = completedAt.String
		}
		if inputs.Valid {
			var parsed any
			if json.Unmarshal([]byte(inputs.String), &parsed) == nil {
				entry["inputs"] = parsed
			}
		}
		if outputs.Valid {
			var parsed any
			if json.Unmarshal([]byte(outputs.String), &parsed) == nil {
				entry["outputs"] = parsed
			}
		}
		if errorDetail.Valid {
			entry["error"] = errorDetail.String
		}

		data, _ := json.MarshalIndent(entry, "", "  ")
		os.WriteFile(filepath.Join(output, "runs", uuid+".json"), data, 0644)
		count++
	}
	return count
}

func exportAuditJSON(auditDB *sql.DB, wsUUID, output string) int {
	rows, err := auditDB.Query(
		`SELECT id, timestamp, session_uuid, run_uuid, operator, event_type, detail, record_hash
		 FROM audit_log WHERE workspace_uuid = ? ORDER BY id ASC`, wsUUID)
	if err != nil {
		return 0
	}
	defer rows.Close()

	var entries []map[string]any
	for rows.Next() {
		var id int64
		var ts, sessionUUID, runUUID, operator, eventType, detail, recordHash string
		rows.Scan(&id, &ts, &sessionUUID, &runUUID, &operator, &eventType, &detail, &recordHash)

		entry := map[string]any{
			"id":          id,
			"timestamp":   ts,
			"operator":    operator,
			"event_type":  eventType,
			"record_hash": recordHash,
		}
		if sessionUUID != "" {
			entry["session_uuid"] = sessionUUID
		}
		if runUUID != "" {
			entry["run_uuid"] = runUUID
		}

		// Parse detail JSON, redacting secrets
		var detailParsed any
		if json.Unmarshal([]byte(detail), &detailParsed) == nil {
			entry["detail"] = detailParsed
		} else {
			entry["detail"] = detail
		}

		entries = append(entries, entry)
	}

	data, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(filepath.Join(output, "audit", "audit.json"), data, 0644)
	return len(entries)
}

// exportMarkdown produces a human-readable markdown evidence bundle.
func exportMarkdown(metaDB, auditDB *sql.DB, wsUUID string, ws interface{}, output string) error {
	now := time.Now().UTC()

	// Gather data
	identities := gatherIdentities(metaDB, wsUUID)
	sessions := gatherSessions(metaDB, wsUUID)
	runs := gatherRuns(metaDB, wsUUID)

	// Also export JSON artifacts alongside markdown
	exportGraphJSON(metaDB, wsUUID, output)
	auditCount := exportAuditJSON(auditDB, wsUUID, output)

	// Write main report
	var sb strings.Builder
	sb.WriteString("# STRATUS Evidence Report\n\n")
	sb.WriteString(fmt.Sprintf("**Workspace ID:** `%s`\n\n", wsUUID))
	sb.WriteString(fmt.Sprintf("**Exported:** %s\n\n", now.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString("---\n\n")

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Count |\n"))
	sb.WriteString(fmt.Sprintf("|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Identities | %d |\n", len(identities)))
	sb.WriteString(fmt.Sprintf("| Sessions | %d |\n", len(sessions)))
	sb.WriteString(fmt.Sprintf("| Module Runs | %d |\n", len(runs)))
	sb.WriteString(fmt.Sprintf("| Audit Events | %d |\n", auditCount))
	sb.WriteString("\n")

	// Identities
	sb.WriteString("## Identities\n\n")
	if len(identities) == 0 {
		sb.WriteString("_No identities recorded._\n\n")
	} else {
		sb.WriteString("| Label | Type | Source | Principal ARN | Account | Acquired |\n")
		sb.WriteString("|-------|------|--------|---------------|---------|----------|\n")
		for _, id := range identities {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | `%s` | %s | %s |\n",
				id["label"], id["principal_type"], id["source_type"],
				id["principal_arn"], id["account_id"], id["acquired_at"]))
		}
		sb.WriteString("\n")
	}

	// Sessions
	sb.WriteString("## Sessions\n\n")
	if len(sessions) == 0 {
		sb.WriteString("_No sessions recorded._\n\n")
	} else {
		sb.WriteString("| Name | Region | Health | Key Hint | Created | Chain Parent |\n")
		sb.WriteString("|------|--------|--------|----------|---------|-------------|\n")
		for _, s := range sessions {
			parent := ""
			if p, ok := s["chain_parent"]; ok && p != "" {
				parent = "`" + p.(string)[:8] + "...`"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | `%s` | %s | %s |\n",
				s["session_name"], s["region"], s["health"],
				s["key_hint"], s["created_at"], parent))
		}
		sb.WriteString("\n")
	}

	// Module Runs
	sb.WriteString("## Module Runs\n\n")
	if len(runs) == 0 {
		sb.WriteString("_No module runs recorded._\n\n")
	} else {
		for _, r := range runs {
			status := r["status"].(string)
			statusIcon := "?"
			switch status {
			case "success":
				statusIcon = "PASS"
			case "error":
				statusIcon = "FAIL"
			case "dry_run":
				statusIcon = "DRY"
			}

			sb.WriteString(fmt.Sprintf("### %s — %s [%s]\n\n", r["module_id"], statusIcon, status))
			sb.WriteString(fmt.Sprintf("- **Run ID:** `%s`\n", r["uuid"]))
			sb.WriteString(fmt.Sprintf("- **Started:** %s\n", r["started_at"]))

			if ca, ok := r["completed_at"]; ok && ca != "" {
				sb.WriteString(fmt.Sprintf("- **Completed:** %s\n", ca))
			}
			if errStr, ok := r["error"]; ok && errStr != "" {
				sb.WriteString(fmt.Sprintf("- **Error:** %s\n", errStr))
			}

			if outputs, ok := r["outputs"]; ok && outputs != "" {
				sb.WriteString("\n<details><summary>Outputs</summary>\n\n```json\n")
				// Pretty-print
				var parsed any
				if json.Unmarshal([]byte(outputs.(string)), &parsed) == nil {
					pretty, _ := json.MarshalIndent(parsed, "", "  ")
					sb.WriteString(string(pretty))
				} else {
					sb.WriteString(outputs.(string))
				}
				sb.WriteString("\n```\n</details>\n")
			}
			sb.WriteString("\n")
		}
	}

	// Graph
	sb.WriteString("## Pivot Graph\n\n")
	var nodeCount, edgeCount int
	metaDB.QueryRow("SELECT COUNT(*) FROM graph_nodes WHERE workspace_uuid = ?", wsUUID).Scan(&nodeCount)
	metaDB.QueryRow("SELECT COUNT(*) FROM graph_edges WHERE workspace_uuid = ?", wsUUID).Scan(&edgeCount)
	sb.WriteString(fmt.Sprintf("- **Nodes:** %d\n", nodeCount))
	sb.WriteString(fmt.Sprintf("- **Edges:** %d\n", edgeCount))
	sb.WriteString(fmt.Sprintf("\nFull graph data exported to `graph/graph.json`.\n\n"))

	// Edges table
	if edgeCount > 0 {
		edgeRows, err := metaDB.Query(
			`SELECT source_node_id, target_node_id, edge_type, confidence
			 FROM graph_edges WHERE workspace_uuid = ? AND is_stale = 0
			 ORDER BY confidence DESC`, wsUUID)
		if err == nil {
			defer edgeRows.Close()
			sb.WriteString("| Source | Target | Type | Confidence |\n")
			sb.WriteString("|--------|--------|------|------------|\n")
			for edgeRows.Next() {
				var src, tgt, edgeType string
				var confidence float64
				edgeRows.Scan(&src, &tgt, &edgeType, &confidence)
				sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %.0f%% |\n",
					truncateARN(src), truncateARN(tgt), edgeType, confidence*100))
			}
			sb.WriteString("\n")
		}
	}

	// Audit summary
	sb.WriteString("## Audit Log\n\n")
	sb.WriteString(fmt.Sprintf("Total audit events: %d\n\n", auditCount))
	sb.WriteString("Full audit log exported to `audit/audit.json`.\n\n")

	// Write the report
	reportPath := filepath.Join(output, "report.md")
	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Also write per-identity markdown files
	for _, id := range identities {
		writeIdentityMarkdown(output, id)
	}

	// Also write per-run markdown files
	for _, r := range runs {
		writeRunMarkdown(output, r)
	}

	fmt.Printf("  Report:     %s\n", reportPath)
	fmt.Printf("  Identities: %d\n", len(identities))
	fmt.Printf("  Sessions:   %d\n", len(sessions))
	fmt.Printf("  Runs:       %d\n", len(runs))
	fmt.Printf("  Audit:      %d events\n", auditCount)
	fmt.Printf("\nEvidence bundle exported to: %s\n", output)
	return nil
}

// Data gathering helpers

func gatherIdentities(db *sql.DB, wsUUID string) []map[string]any {
	rows, err := db.Query(
		`SELECT uuid, label, account_id, principal_arn, principal_type, source_type, acquired_at, tags, is_archived
		 FROM identities WHERE workspace_uuid = ?`, wsUUID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var uuid, label, accountID, principalARN, principalType, sourceType, acquiredAt, tags string
		var isArchived int
		rows.Scan(&uuid, &label, &accountID, &principalARN, &principalType, &sourceType, &acquiredAt, &tags, &isArchived)
		result = append(result, map[string]any{
			"uuid":           uuid,
			"label":          label,
			"account_id":     accountID,
			"principal_arn":  principalARN,
			"principal_type": principalType,
			"source_type":    sourceType,
			"acquired_at":    acquiredAt,
			"tags":           tags,
			"is_archived":    isArchived != 0,
		})
	}
	return result
}

func gatherSessions(db *sql.DB, wsUUID string) []map[string]any {
	rows, err := db.Query(
		`SELECT uuid, identity_uuid, aws_access_key_id, session_name, region, expiry,
		        health_status, created_at, chain_parent_session_uuid
		 FROM sessions WHERE workspace_uuid = ?`, wsUUID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var uuid, identityUUID, accessKeyID, name, region, health, createdAt string
		var expiry, chainParent sql.NullString
		rows.Scan(&uuid, &identityUUID, &accessKeyID, &name, &region, &expiry, &health, &createdAt, &chainParent)

		keyHint := accessKeyID
		if len(keyHint) > 8 {
			keyHint = keyHint[:4] + "..." + keyHint[len(keyHint)-4:]
		}

		entry := map[string]any{
			"uuid":          uuid,
			"identity_uuid": identityUUID,
			"key_hint":      keyHint,
			"session_name":  name,
			"region":        region,
			"health":        health,
			"created_at":    createdAt,
		}
		if expiry.Valid {
			entry["expiry"] = expiry.String
		}
		if chainParent.Valid {
			entry["chain_parent"] = chainParent.String
		}
		result = append(result, entry)
	}
	return result
}

func gatherRuns(db *sql.DB, wsUUID string) []map[string]any {
	rows, err := db.Query(
		`SELECT uuid, module_id, module_version, session_uuid, status, started_at, completed_at, inputs, outputs, error_detail
		 FROM module_runs WHERE workspace_uuid = ? ORDER BY started_at DESC`, wsUUID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var uuid, moduleID, moduleVersion, sessionUUID, status, startedAt string
		var completedAt, inputs, outputs, errorDetail sql.NullString
		rows.Scan(&uuid, &moduleID, &moduleVersion, &sessionUUID, &status, &startedAt, &completedAt, &inputs, &outputs, &errorDetail)

		entry := map[string]any{
			"uuid":           uuid,
			"module_id":      moduleID,
			"module_version": moduleVersion,
			"session_uuid":   sessionUUID,
			"status":         status,
			"started_at":     startedAt,
		}
		if completedAt.Valid {
			entry["completed_at"] = completedAt.String
		}
		if inputs.Valid {
			entry["inputs"] = inputs.String
		}
		if outputs.Valid {
			entry["outputs"] = outputs.String
		}
		if errorDetail.Valid {
			entry["error"] = errorDetail.String
		}
		result = append(result, entry)
	}
	return result
}

func writeIdentityMarkdown(output string, id map[string]any) {
	uuid := id["uuid"].(string)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Identity: %s\n\n", id["label"]))
	sb.WriteString(fmt.Sprintf("- **UUID:** `%s`\n", uuid))
	sb.WriteString(fmt.Sprintf("- **Type:** %s\n", id["principal_type"]))
	sb.WriteString(fmt.Sprintf("- **Source:** %s\n", id["source_type"]))
	sb.WriteString(fmt.Sprintf("- **Principal ARN:** `%s`\n", id["principal_arn"]))
	sb.WriteString(fmt.Sprintf("- **Account ID:** %s\n", id["account_id"]))
	sb.WriteString(fmt.Sprintf("- **Acquired:** %s\n", id["acquired_at"]))
	if archived, ok := id["is_archived"].(bool); ok && archived {
		sb.WriteString("- **Status:** ARCHIVED\n")
	}
	os.WriteFile(filepath.Join(output, "identities", uuid+".md"), []byte(sb.String()), 0644)
}

func writeRunMarkdown(output string, r map[string]any) {
	uuid := r["uuid"].(string)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Module Run: %s\n\n", r["module_id"]))
	sb.WriteString(fmt.Sprintf("- **Run ID:** `%s`\n", uuid))
	sb.WriteString(fmt.Sprintf("- **Module Version:** %s\n", r["module_version"]))
	sb.WriteString(fmt.Sprintf("- **Status:** %s\n", r["status"]))
	sb.WriteString(fmt.Sprintf("- **Session:** `%s`\n", r["session_uuid"]))
	sb.WriteString(fmt.Sprintf("- **Started:** %s\n", r["started_at"]))
	if ca, ok := r["completed_at"]; ok && ca != "" {
		sb.WriteString(fmt.Sprintf("- **Completed:** %s\n", ca))
	}
	if errStr, ok := r["error"]; ok && errStr != "" {
		sb.WriteString(fmt.Sprintf("\n## Error\n\n```\n%s\n```\n", errStr))
	}
	if inputs, ok := r["inputs"]; ok && inputs != "" {
		sb.WriteString("\n## Inputs\n\n```json\n")
		prettyPrintJSON(&sb, inputs.(string))
		sb.WriteString("\n```\n")
	}
	if outputs, ok := r["outputs"]; ok && outputs != "" {
		sb.WriteString("\n## Outputs\n\n```json\n")
		prettyPrintJSON(&sb, outputs.(string))
		sb.WriteString("\n```\n")
	}
	os.WriteFile(filepath.Join(output, "runs", uuid+".md"), []byte(sb.String()), 0644)
}

func prettyPrintJSON(sb *strings.Builder, raw string) {
	var parsed any
	if json.Unmarshal([]byte(raw), &parsed) == nil {
		pretty, _ := json.MarshalIndent(parsed, "", "  ")
		sb.WriteString(string(pretty))
	} else {
		sb.WriteString(raw)
	}
}

func truncateARN(arn string) string {
	// Show last component of ARN for readability
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return ".../" + parts[len(parts)-1]
	}
	if len(arn) > 40 {
		return arn[:37] + "..."
	}
	return arn
}
