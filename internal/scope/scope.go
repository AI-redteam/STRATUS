// Package scope implements the blast radius enforcement system.
// Operations targeting resources outside declared scope are blocked by default.
package scope

import (
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/core"
)

// Checker evaluates whether operations fall within the workspace scope.
type Checker struct {
	scope core.Scope
}

// NewChecker creates a scope checker for the given workspace scope.
func NewChecker(scope core.Scope) *Checker {
	return &Checker{scope: scope}
}

// CheckAccount verifies an AWS account ID is in scope.
func (c *Checker) CheckAccount(accountID string) error {
	if len(c.scope.AccountIDs) == 0 {
		return nil // No account restriction
	}
	for _, id := range c.scope.AccountIDs {
		if id == accountID {
			return nil
		}
	}
	return &ScopeViolation{
		Resource: "account:" + accountID,
		Reason:   fmt.Sprintf("account %s is not in scope (allowed: %s)", accountID, strings.Join(c.scope.AccountIDs, ", ")),
	}
}

// CheckRegion verifies an AWS region is in scope.
func (c *Checker) CheckRegion(region string) error {
	if len(c.scope.Regions) == 0 {
		return nil // No region restriction
	}
	for _, r := range c.scope.Regions {
		if r == region {
			return nil
		}
	}
	return &ScopeViolation{
		Resource: "region:" + region,
		Reason:   fmt.Sprintf("region %s is not in scope (allowed: %s)", region, strings.Join(c.scope.Regions, ", ")),
	}
}

// CheckPartition verifies the AWS partition.
func (c *Checker) CheckPartition(partition string) error {
	if c.scope.Partition == "" {
		return nil
	}
	if c.scope.Partition != partition {
		return &ScopeViolation{
			Resource: "partition:" + partition,
			Reason:   fmt.Sprintf("partition %s is not in scope (allowed: %s)", partition, c.scope.Partition),
		}
	}
	return nil
}

// CheckARN validates that an ARN's account and region are in scope.
func (c *Checker) CheckARN(arn string) error {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 {
		return fmt.Errorf("invalid ARN format: %s", arn)
	}

	// parts[1] = partition, parts[3] = region, parts[4] = account
	if err := c.CheckPartition(parts[1]); err != nil {
		return err
	}
	if parts[3] != "" { // Some ARNs have empty region (e.g., IAM)
		if err := c.CheckRegion(parts[3]); err != nil {
			return err
		}
	}
	if parts[4] != "" {
		if err := c.CheckAccount(parts[4]); err != nil {
			return err
		}
	}
	return nil
}

// IsInScope returns true if the account+region combination is within scope.
func (c *Checker) IsInScope(accountID, region string) bool {
	if err := c.CheckAccount(accountID); err != nil {
		return false
	}
	if err := c.CheckRegion(region); err != nil {
		return false
	}
	return true
}

// ScopeViolation represents an out-of-scope access attempt.
type ScopeViolation struct {
	Resource string
	Reason   string
}

func (sv *ScopeViolation) Error() string {
	return fmt.Sprintf("scope violation [%s]: %s", sv.Resource, sv.Reason)
}

// IsScopeViolation checks if an error is a scope violation.
func IsScopeViolation(err error) bool {
	_, ok := err.(*ScopeViolation)
	return ok
}
