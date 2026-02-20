package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CognitoPrivescCheckModule identifies Cognito privilege escalation paths
// based on techniques documented in hacktricks-cloud. Checks for unauthenticated
// IAM credential access, identity pool role swapping, user pool group role
// escalation, self-registration to authenticated role, MFA bypass, and
// identity provider manipulation.
type CognitoPrivescCheckModule struct {
	factory *aws.ClientFactory
}

func (m *CognitoPrivescCheckModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.cognito.privesc-check",
		Name:        "Cognito Privilege Escalation Check",
		Version:     "1.0.0",
		Description: "Identifies Cognito privilege escalation paths including: unauthenticated IAM credential theft via Identity Pool IDs, SetIdentityPoolRoles to assign arbitrary roles, UpdateIdentityPool to inject attacker IdPs or enable unauth access, AdminSetUserPassword for user impersonation, AdminAddUserToGroup for group role escalation, self-registration for authenticated role access, MFA bypass via AdminSetUserSettings/SetUserPoolMfaConfig, and identity provider manipulation for persistence.",
		Services:    []string{"cognito-idp", "cognito-identity"},
		RequiredActions: []string{
			"cognito-idp:ListUserPools",
			"cognito-idp:DescribeUserPool",
			"cognito-idp:ListGroups",
			"cognito-identity:ListIdentityPools",
			"cognito-identity:DescribeIdentityPool",
			"cognito-identity:GetIdentityPoolRoles",
		},
		RequiredResources: []string{"*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_pools", Type: "int", Default: 60, Description: "Maximum pools per type to check"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "privesc_paths", Type: "[]map", Description: "Identified privilege escalation paths"},
			{Name: "path_count", Type: "int", Description: "Total escalation paths found"},
			{Name: "unauthenticated_targets", Type: "[]map", Description: "Identity pools accessible without authentication"},
			{Name: "summary", Type: "map", Description: "Aggregate summary"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1136/",
			"https://attack.mitre.org/techniques/T1098/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Cognito", SortOrder: 2},
	}
}

func (m *CognitoPrivescCheckModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool", "cognito-idp:ListGroups",
			"cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
			"cognito-identity:GetIdentityPoolRoles",
		},
		Confidence: 1.0,
	}
}

func (m *CognitoPrivescCheckModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate Cognito User Pools and Identity Pools to identify privilege escalation paths including unauthenticated credential access, role swapping, group escalation, and MFA bypass.",
		WouldMutate: false,
	}
}

func (m *CognitoPrivescCheckModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxPools := ctx.InputInt("max_pools")
	if maxPools <= 0 {
		maxPools = 60
	}

	var privescPaths []map[string]any
	var unauthTargets []map[string]any
	roleSet := make(map[string]bool)

	prog.Total(4)

	// --- Step 1: Identity Pool analysis ---
	prog.Update(1, "Analyzing Identity Pools for unauthenticated access")

	identityPools, err := m.factory.ListCognitoIdentityPools(bgCtx, creds)
	if err == nil {
		for i, pool := range identityPools {
			if i >= maxPools {
				break
			}

			detail, err := m.factory.DescribeCognitoIdentityPool(bgCtx, creds, pool.PoolID)
			if err != nil {
				continue
			}

			roles, err := m.factory.GetCognitoIdentityPoolRoles(bgCtx, creds, pool.PoolID)
			if err != nil {
				continue
			}

			if roles.AuthenticatedRole != "" {
				roleSet[roles.AuthenticatedRole] = true
			}
			if roles.UnauthenticatedRole != "" {
				roleSet[roles.UnauthenticatedRole] = true
			}

			// Technique 1: Unauthenticated IAM credential theft
			if detail.AllowUnauthenticated {
				target := map[string]any{
					"pool_id":      pool.PoolID,
					"pool_name":    pool.PoolName,
					"role_arn":     roles.UnauthenticatedRole,
					"classic_flow": detail.AllowClassicFlow,
				}
				unauthTargets = append(unauthTargets, target)

				severity := "high"
				desc := fmt.Sprintf("Identity Pool %s (%s) allows unauthenticated access. Use GetId + GetCredentialsForIdentity with just the Pool ID to obtain IAM credentials.", pool.PoolName, pool.PoolID)
				if detail.AllowClassicFlow {
					severity = "critical"
					desc += " Classic flow is also enabled — use GetOpenIdToken + AssumeRoleWithWebIdentity to bypass enhanced flow session policy restrictions for UNRESTRICTED role access."
				}

				privescPaths = append(privescPaths, map[string]any{
					"finding":          "UnauthenticatedCredentials",
					"severity":         severity,
					"principal_type":   "cognito_identity_pool",
					"principal_name":   pool.PoolName,
					"principal_arn":    pool.PoolID,
					"target_role":     roles.UnauthenticatedRole,
					"description":     desc,
					"required_actions": []string{"(none — unauthenticated)"},
					"reference":        "T1078.004",
				})
			}

			// Technique 2: SetIdentityPoolRoles — assign arbitrary roles
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "SetIdentityPoolRoles",
				"severity":         "critical",
				"principal_type":   "cognito_identity_pool",
				"principal_name":   pool.PoolName,
				"principal_arn":    pool.PoolID,
				"target_role":     roles.AuthenticatedRole,
				"description":     fmt.Sprintf("cognito-identity:SetIdentityPoolRoles on %s can replace the authenticated/unauthenticated role mappings with any IAM role. Combined with GetCredentialsForIdentity for full role access.", pool.PoolName),
				"required_actions": []string{
					"cognito-identity:SetIdentityPoolRoles",
					"iam:PassRole",
				},
				"reference": "T1098",
			})

			// Technique 3: UpdateIdentityPool — inject attacker IdP or enable unauth
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "UpdateIdentityPool",
				"severity":         "critical",
				"principal_type":   "cognito_identity_pool",
				"principal_name":   pool.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-identity:UpdateIdentityPool on %s can: (1) add attacker-controlled identity providers, (2) enable unauthenticated access, (3) enable classic flow to bypass session policy restrictions.", pool.PoolName),
				"required_actions": []string{
					"cognito-identity:UpdateIdentityPool",
				},
				"reference": "T1098",
			})
		}
	}

	// --- Step 2: User Pool analysis ---
	prog.Update(2, "Analyzing User Pools for self-registration and group roles")

	userPools, err := m.factory.ListCognitoUserPools(bgCtx, creds)
	if err == nil {
		for i, pool := range userPools {
			if i >= maxPools {
				break
			}

			detail, err := m.factory.DescribeCognitoUserPool(bgCtx, creds, pool.PoolID)
			if err != nil {
				continue
			}

			// Technique 4: Self-registration for authenticated IAM role
			if detail.SelfSignUpEnabled {
				privescPaths = append(privescPaths, map[string]any{
					"finding":          "SelfRegistration",
					"severity":         "high",
					"principal_type":   "cognito_user_pool",
					"principal_name":   detail.PoolName,
					"principal_arn":    pool.PoolID,
					"description":     fmt.Sprintf("User Pool %s (%s) allows self-registration. Create an account with cognito-idp:SignUp, confirm it, authenticate, then use the ID token with a linked Identity Pool to obtain authenticated IAM role credentials.", detail.PoolName, pool.PoolID),
					"required_actions": []string{"(none — self-registration)"},
					"reference":        "T1136",
				})
			}

			// Technique 5: MFA bypass
			if detail.MFAConfiguration != "ON" {
				privescPaths = append(privescPaths, map[string]any{
					"finding":          "MFABypass",
					"severity":         "medium",
					"principal_type":   "cognito_user_pool",
					"principal_name":   detail.PoolName,
					"principal_arn":    pool.PoolID,
					"description":     fmt.Sprintf("User Pool %s MFA is %s. With cognito-idp:SetUserPoolMfaConfig or AdminSetUserMFAPreference, MFA can be disabled or redirected to attacker-controlled device.", detail.PoolName, detail.MFAConfiguration),
					"required_actions": []string{
						"cognito-idp:SetUserPoolMfaConfig",
					},
					"reference": "T1098",
				})
			}

			// Technique 6: AdminSetUserPassword — impersonate any user
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "AdminSetUserPassword",
				"severity":         "critical",
				"principal_type":   "cognito_user_pool",
				"principal_name":   detail.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-idp:AdminSetUserPassword on User Pool %s can set any user's password, enabling full account impersonation (bypasses MFA if set to permanent).", detail.PoolName),
				"required_actions": []string{
					"cognito-idp:AdminSetUserPassword",
				},
				"reference": "T1098",
			})

			// Technique 7: AdminCreateUser
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "AdminCreateUser",
				"severity":         "high",
				"principal_type":   "cognito_user_pool",
				"principal_name":   detail.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-idp:AdminCreateUser on User Pool %s can create arbitrary users with controlled attributes, bypassing self-registration restrictions.", detail.PoolName),
				"required_actions": []string{
					"cognito-idp:AdminCreateUser",
				},
				"reference": "T1136",
			})

			// Enumerate groups with IAM roles
			groups, err := m.factory.ListCognitoGroups(bgCtx, creds, pool.PoolID)
			if err == nil {
				for _, g := range groups {
					if g.RoleARN != "" {
						roleSet[g.RoleARN] = true

						// Technique 8: AdminAddUserToGroup — escalate to group role
						privescPaths = append(privescPaths, map[string]any{
							"finding":          "AdminAddUserToGroup",
							"severity":         "high",
							"principal_type":   "cognito_user_pool_group",
							"principal_name":   fmt.Sprintf("%s/%s", detail.PoolName, g.GroupName),
							"principal_arn":    fmt.Sprintf("%s/group/%s", pool.PoolID, g.GroupName),
							"target_role":     g.RoleARN,
							"description":     fmt.Sprintf("cognito-idp:AdminAddUserToGroup can add any user to group %s in User Pool %s, granting access to IAM role %s.", g.GroupName, detail.PoolName, g.RoleARN),
							"required_actions": []string{
								"cognito-idp:AdminAddUserToGroup",
							},
							"reference": "T1098",
						})

						// Technique 9: CreateGroup/UpdateGroup with iam:PassRole
						privescPaths = append(privescPaths, map[string]any{
							"finding":          "CreateGroupWithRole",
							"severity":         "critical",
							"principal_type":   "cognito_user_pool",
							"principal_name":   detail.PoolName,
							"principal_arn":    pool.PoolID,
							"target_role":     g.RoleARN,
							"description":     fmt.Sprintf("cognito-idp:CreateGroup or UpdateGroup with iam:PassRole on User Pool %s can create/modify groups with arbitrary IAM roles.", detail.PoolName),
							"required_actions": []string{
								"cognito-idp:CreateGroup",
								"iam:PassRole",
							},
							"reference": "T1098",
						})
					}
				}
			}

			// Technique 10: CreateIdentityProvider for persistence
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "CreateIdentityProvider",
				"severity":         "high",
				"principal_type":   "cognito_user_pool",
				"principal_name":   detail.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-idp:CreateIdentityProvider on User Pool %s can add an attacker-controlled SAML/OIDC identity provider for persistent access.", detail.PoolName),
				"required_actions": []string{
					"cognito-idp:CreateIdentityProvider",
				},
				"reference": "T1098",
			})

			// Technique 11: CreateUserPoolClient — create permissive client
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "CreateUserPoolClient",
				"severity":         "medium",
				"principal_type":   "cognito_user_pool",
				"principal_name":   detail.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-idp:CreateUserPoolClient on User Pool %s can create a new app client with all auth flows enabled, no client secret, extended token validity, and token revocation disabled.", detail.PoolName),
				"required_actions": []string{
					"cognito-idp:CreateUserPoolClient",
				},
				"reference": "T1098",
			})

			// Technique 12: SetRiskConfiguration — disable compromise detection
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "DisableCompromiseDetection",
				"severity":         "medium",
				"principal_type":   "cognito_user_pool",
				"principal_name":   detail.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-idp:SetRiskConfiguration on User Pool %s can disable Advanced Security compromise detection, allowing credential stuffing and account takeover without alerts.", detail.PoolName),
				"required_actions": []string{
					"cognito-idp:SetRiskConfiguration",
				},
				"reference": "T1098",
			})
		}
	}

	// --- Step 3: AdminUpdateUserAttributes for app-level privesc ---
	prog.Update(3, "Checking attribute manipulation paths")

	if userPools != nil {
		for i, pool := range userPools {
			if i >= maxPools || pool.PoolID == "" {
				break
			}
			privescPaths = append(privescPaths, map[string]any{
				"finding":          "AdminUpdateUserAttributes",
				"severity":         "medium",
				"principal_type":   "cognito_user_pool",
				"principal_name":   pool.PoolName,
				"principal_arn":    pool.PoolID,
				"description":     fmt.Sprintf("cognito-idp:AdminUpdateUserAttributes on User Pool %s can modify custom attributes (e.g., isAdmin, role, tier) for application-level privilege escalation, or change email/phone for account impersonation.", pool.PoolName),
				"required_actions": []string{
					"cognito-idp:AdminUpdateUserAttributes",
				},
				"reference": "T1098",
			})
		}
	}

	prog.Update(4, "Building summary")

	findingCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	for _, p := range privescPaths {
		if t, ok := p["finding"].(string); ok {
			findingCounts[t]++
		}
		if s, ok := p["severity"].(string); ok {
			severityCounts[s]++
		}
	}

	userPoolCount := len(userPools)
	if userPoolCount > maxPools {
		userPoolCount = maxPools
	}
	identityPoolCount := len(identityPools)
	if identityPoolCount > maxPools {
		identityPoolCount = maxPools
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"privesc_paths":           privescPaths,
			"path_count":              len(privescPaths),
			"unauthenticated_targets": unauthTargets,
			"summary": map[string]any{
				"total_paths":      len(privescPaths),
				"unique_roles":     len(roleSet),
				"user_pools":       userPoolCount,
				"identity_pools":   identityPoolCount,
				"unauth_targets":   len(unauthTargets),
				"finding_counts":   findingCounts,
				"severity_counts":  severityCounts,
			},
		},
	}
}

func (m *CognitoPrivescCheckModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
