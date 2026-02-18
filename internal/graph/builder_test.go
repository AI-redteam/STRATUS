package graph

import (
	"testing"
)

func TestParseTrustPolicy_SimpleRole(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	principals, constraints, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(principals))
	}
	if principals[0] != "arn:aws:iam::123456789012:root" {
		t.Errorf("unexpected principal: %s", principals[0])
	}
	if constraints[0] != nil {
		t.Errorf("expected nil constraints, got %v", constraints[0])
	}
}

func TestParseTrustPolicy_MultiplePrincipals(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {
				"AWS": [
					"arn:aws:iam::111111111111:role/DevRole",
					"arn:aws:iam::222222222222:root"
				]
			},
			"Action": "sts:AssumeRole"
		}]
	}`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(principals))
	}
}

func TestParseTrustPolicy_ServicePrincipal(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "lambda.amazonaws.com"},
			"Action": "sts:AssumeRole"
		}]
	}`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(principals))
	}
	if principals[0] != "service:lambda.amazonaws.com" {
		t.Errorf("unexpected principal: %s", principals[0])
	}
}

func TestParseTrustPolicy_MFAConstraint(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:user/admin"},
			"Action": "sts:AssumeRole",
			"Condition": {
				"Bool": {
					"aws:MultiFactorAuthPresent": "true"
				}
			}
		}]
	}`

	principals, constraints, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(principals))
	}
	if constraints[0] == nil {
		t.Fatal("expected constraints, got nil")
	}
	if constraints[0]["mfa_required"] != true {
		t.Errorf("expected mfa_required=true, got %v", constraints[0]["mfa_required"])
	}
}

func TestParseTrustPolicy_ExternalID(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringEquals": {
					"sts:ExternalId": "unique-id-123"
				}
			}
		}]
	}`

	_, constraints, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if constraints[0] == nil {
		t.Fatal("expected constraints")
	}
	if constraints[0]["external_id_required"] != true {
		t.Error("expected external_id_required")
	}
}

func TestParseTrustPolicy_WildcardPrincipal(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRole"
		}]
	}`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 || principals[0] != "*" {
		t.Errorf("expected wildcard principal, got %v", principals)
	}
}

func TestParseTrustPolicy_DenyStatement(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
				"Action": "sts:AssumeRole"
			},
			{
				"Effect": "Deny",
				"Principal": {"AWS": "arn:aws:iam::999999999999:root"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the Allow statement should produce a principal
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal (deny should be skipped), got %d", len(principals))
	}
}

func TestParseTrustPolicy_URLEncoded(t *testing.T) {
	doc := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(principals))
	}
}

func TestParseTrustPolicy_FederatedPrincipal(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": "cognito-identity.amazonaws.com"},
			"Action": "sts:AssumeRoleWithWebIdentity"
		}]
	}`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(principals))
	}
	if principals[0] != "federated:cognito-identity.amazonaws.com" {
		t.Errorf("unexpected principal: %s", principals[0])
	}
}

func TestParseTrustPolicy_AccountID(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "123456789012"},
			"Action": "sts:AssumeRole"
		}]
	}`

	principals, _, err := parseTrustPolicy(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(principals))
	}
	if principals[0] != "arn:aws:iam::123456789012:root" {
		t.Errorf("expected account root ARN, got %s", principals[0])
	}
}

func TestDiffSnapshots(t *testing.T) {
	old := []byte(`{
		"nodes": [
			{"id": "arn:aws:iam::123:role/A", "type": "iam_role"},
			{"id": "arn:aws:iam::123:role/B", "type": "iam_role"}
		],
		"edges": [
			{"source_node_id": "arn:aws:iam::123:role/A", "target_node_id": "arn:aws:iam::123:role/B", "edge_type": "can_assume"}
		]
	}`)

	new := []byte(`{
		"nodes": [
			{"id": "arn:aws:iam::123:role/A", "type": "iam_role"},
			{"id": "arn:aws:iam::123:role/C", "type": "iam_role"}
		],
		"edges": [
			{"source_node_id": "arn:aws:iam::123:role/A", "target_node_id": "arn:aws:iam::123:role/C", "edge_type": "can_assume"}
		]
	}`)

	diff, err := DiffSnapshots(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(diff.NodesAdded) != 1 || diff.NodesAdded[0] != "arn:aws:iam::123:role/C" {
		t.Errorf("unexpected nodes added: %v", diff.NodesAdded)
	}
	if len(diff.NodesRemoved) != 1 || diff.NodesRemoved[0] != "arn:aws:iam::123:role/B" {
		t.Errorf("unexpected nodes removed: %v", diff.NodesRemoved)
	}
	if len(diff.EdgesAdded) != 1 {
		t.Errorf("expected 1 edge added, got %d", len(diff.EdgesAdded))
	}
	if len(diff.EdgesRemoved) != 1 {
		t.Errorf("expected 1 edge removed, got %d", len(diff.EdgesRemoved))
	}
}

func TestInferNodeType(t *testing.T) {
	tests := []struct {
		arn      string
		expected string
	}{
		{"arn:aws:iam::123:user/admin", "iam_user"},
		{"arn:aws:iam::123:role/DevRole", "iam_role"},
		{"arn:aws:iam::123:root", "account_root"},
		{"arn:aws:sts::123:assumed-role/DevRole/session", "assumed_role"},
	}

	for _, tc := range tests {
		got := inferNodeType(tc.arn)
		if got != tc.expected {
			t.Errorf("inferNodeType(%s) = %s, want %s", tc.arn, got, tc.expected)
		}
	}
}
