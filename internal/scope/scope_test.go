package scope

import (
	"testing"

	"github.com/stratus-framework/stratus/internal/core"
)

func TestCheckAccount(t *testing.T) {
	checker := NewChecker(core.Scope{
		AccountIDs: []string{"123456789012", "999888777666"},
	})

	if err := checker.CheckAccount("123456789012"); err != nil {
		t.Errorf("Expected in-scope account to pass: %v", err)
	}

	if err := checker.CheckAccount("111111111111"); err == nil {
		t.Error("Expected out-of-scope account to fail")
	} else if !IsScopeViolation(err) {
		t.Errorf("Expected ScopeViolation error, got %T", err)
	}
}

func TestCheckRegion(t *testing.T) {
	checker := NewChecker(core.Scope{
		Regions: []string{"us-east-1", "us-west-2"},
	})

	if err := checker.CheckRegion("us-east-1"); err != nil {
		t.Errorf("Expected in-scope region to pass: %v", err)
	}

	if err := checker.CheckRegion("eu-west-1"); err == nil {
		t.Error("Expected out-of-scope region to fail")
	}
}

func TestCheckARN(t *testing.T) {
	checker := NewChecker(core.Scope{
		AccountIDs: []string{"123456789012"},
		Regions:    []string{"us-east-1"},
		Partition:  "aws",
	})

	if err := checker.CheckARN("arn:aws:iam::123456789012:role/Test"); err != nil {
		t.Errorf("Expected in-scope ARN to pass: %v", err)
	}

	if err := checker.CheckARN("arn:aws:ec2:us-east-1:123456789012:instance/i-123"); err != nil {
		t.Errorf("Expected in-scope regional ARN to pass: %v", err)
	}

	if err := checker.CheckARN("arn:aws:ec2:eu-west-1:123456789012:instance/i-123"); err == nil {
		t.Error("Expected out-of-scope region ARN to fail")
	}

	if err := checker.CheckARN("arn:aws-cn:iam::123456789012:role/Test"); err == nil {
		t.Error("Expected wrong partition to fail")
	}
}

func TestUnrestrictedScope(t *testing.T) {
	checker := NewChecker(core.Scope{})

	if err := checker.CheckAccount("anything"); err != nil {
		t.Errorf("Unrestricted scope should allow any account: %v", err)
	}
	if err := checker.CheckRegion("anything"); err != nil {
		t.Errorf("Unrestricted scope should allow any region: %v", err)
	}
}

func TestIsInScope(t *testing.T) {
	checker := NewChecker(core.Scope{
		AccountIDs: []string{"123456789012"},
		Regions:    []string{"us-east-1"},
	})

	if !checker.IsInScope("123456789012", "us-east-1") {
		t.Error("Expected in-scope")
	}
	if checker.IsInScope("123456789012", "eu-west-1") {
		t.Error("Expected out-of-scope region")
	}
	if checker.IsInScope("999999999999", "us-east-1") {
		t.Error("Expected out-of-scope account")
	}
}
