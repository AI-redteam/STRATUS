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
					"pool_id":   pool.PoolID,
					"pool_name": pool.PoolName,
					"role_arn":  roles.UnauthenticatedRole,
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
					"technique":   "UnauthenticatedCredentials",
					"severity":    severity,
					"resource":    pool.PoolID,
					"target_role": roles.UnauthenticatedRole,
					"description": desc,
					"required_permissions": []string{"(none — unauthenticated)"},
				})
			}

			// Technique 2: SetIdentityPoolRoles — assign arbitrary roles
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "SetIdentityPoolRoles",
				"severity":    "critical",
				"resource":    pool.PoolID,
				"target_role": roles.AuthenticatedRole,
				"description": fmt.Sprintf("cognito-identity:SetIdentityPoolRoles on %s can replace the authenticated/unauthenticated role mappings with any IAM role. Combined with GetCredentialsForIdentity for full role access.", pool.PoolName),
				"required_permissions": []string{
					"cognito-identity:SetIdentityPoolRoles",
					"iam:PassRole",
				},
			})

			// Technique 3: UpdateIdentityPool — inject attacker IdP or enable unauth
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "UpdateIdentityPool",
				"severity":    "critical",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-identity:UpdateIdentityPool on %s can: (1) add attacker-controlled identity providers, (2) enable unauthenticated access, (3) enable classic flow to bypass session policy restrictions.", pool.PoolName),
				"required_permissions": []string{
					"cognito-identity:UpdateIdentityPool",
				},
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
					"technique":   "SelfRegistration",
					"severity":    "high",
					"resource":    pool.PoolID,
					"description": fmt.Sprintf("User Pool %s (%s) allows self-registration. Create an account with cognito-idp:SignUp, confirm it, authenticate, then use the ID token with a linked Identity Pool to obtain authenticated IAM role credentials.", detail.PoolName, pool.PoolID),
					"required_permissions": []string{"(none — self-registration)"},
				})
			}

			// Technique 5: MFA bypass
			if detail.MFAConfiguration != "ON" {
				privescPaths = append(privescPaths, map[string]any{
					"technique":   "MFABypass",
					"severity":    "medium",
					"resource":    pool.PoolID,
					"description": fmt.Sprintf("User Pool %s MFA is %s. With cognito-idp:SetUserPoolMfaConfig or AdminSetUserMFAPreference, MFA can be disabled or redirected to attacker-controlled device.", detail.PoolName, detail.MFAConfiguration),
					"required_permissions": []string{
						"cognito-idp:SetUserPoolMfaConfig",
					},
				})
			}

			// Technique 6: AdminSetUserPassword — impersonate any user
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "AdminSetUserPassword",
				"severity":    "critical",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-idp:AdminSetUserPassword on User Pool %s can set any user's password, enabling full account impersonation (bypasses MFA if set to permanent).", detail.PoolName),
				"required_permissions": []string{
					"cognito-idp:AdminSetUserPassword",
				},
			})

			// Technique 7: AdminCreateUser
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "AdminCreateUser",
				"severity":    "high",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-idp:AdminCreateUser on User Pool %s can create arbitrary users with controlled attributes, bypassing self-registration restrictions.", detail.PoolName),
				"required_permissions": []string{
					"cognito-idp:AdminCreateUser",
				},
			})

			// Enumerate groups with IAM roles
			groups, err := m.factory.ListCognitoGroups(bgCtx, creds, pool.PoolID)
			if err == nil {
				for _, g := range groups {
					if g.RoleARN != "" {
						roleSet[g.RoleARN] = true

						// Technique 8: AdminAddUserToGroup — escalate to group role
						privescPaths = append(privescPaths, map[string]any{
							"technique":   "AdminAddUserToGroup",
							"severity":    "high",
							"resource":    fmt.Sprintf("%s/group/%s", pool.PoolID, g.GroupName),
							"target_role": g.RoleARN,
							"description": fmt.Sprintf("cognito-idp:AdminAddUserToGroup can add any user to group %s in User Pool %s, granting access to IAM role %s.", g.GroupName, detail.PoolName, g.RoleARN),
							"required_permissions": []string{
								"cognito-idp:AdminAddUserToGroup",
							},
						})

						// Technique 9: CreateGroup/UpdateGroup with iam:PassRole
						privescPaths = append(privescPaths, map[string]any{
							"technique":   "CreateGroupWithRole",
							"severity":    "critical",
							"resource":    pool.PoolID,
							"target_role": g.RoleARN,
							"description": fmt.Sprintf("cognito-idp:CreateGroup or UpdateGroup with iam:PassRole on User Pool %s can create/modify groups with arbitrary IAM roles.", detail.PoolName),
							"required_permissions": []string{
								"cognito-idp:CreateGroup",
								"iam:PassRole",
							},
						})
					}
				}
			}

			// Technique 10: CreateIdentityProvider for persistence
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "CreateIdentityProvider",
				"severity":    "high",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-idp:CreateIdentityProvider on User Pool %s can add an attacker-controlled SAML/OIDC identity provider for persistent access.", detail.PoolName),
				"required_permissions": []string{
					"cognito-idp:CreateIdentityProvider",
				},
			})

			// Technique 11: CreateUserPoolClient — create permissive client
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "CreateUserPoolClient",
				"severity":    "medium",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-idp:CreateUserPoolClient on User Pool %s can create a new app client with all auth flows enabled, no client secret, extended token validity, and token revocation disabled.", detail.PoolName),
				"required_permissions": []string{
					"cognito-idp:CreateUserPoolClient",
				},
			})

			// Technique 12: SetRiskConfiguration — disable compromise detection
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "DisableCompromiseDetection",
				"severity":    "medium",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-idp:SetRiskConfiguration on User Pool %s can disable Advanced Security compromise detection, allowing credential stuffing and account takeover without alerts.", detail.PoolName),
				"required_permissions": []string{
					"cognito-idp:SetRiskConfiguration",
				},
			})
		}
	}

	// --- Step 3: AdminUpdateUserAttributes for app-level privesc ---
	prog.Update(3, "Checking attribute manipulation paths")

	if len(userPools) > 0 {
		for _, pool := range userPools {
			if pool.PoolID == "" {
				continue
			}
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "AdminUpdateUserAttributes",
				"severity":    "medium",
				"resource":    pool.PoolID,
				"description": fmt.Sprintf("cognito-idp:AdminUpdateUserAttributes on User Pool %s can modify custom attributes (e.g., isAdmin, role, tier) for application-level privilege escalation, or change email/phone for account impersonation.", pool.PoolName),
				"required_permissions": []string{
					"cognito-idp:AdminUpdateUserAttributes",
				},
			})
			break // One entry covers all pools
		}
	}

	prog.Update(4, "Building summary")

	techniqueCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	for _, p := range privescPaths {
		if t, ok := p["technique"].(string); ok {
			techniqueCounts[t]++
		}
		if s, ok := p["severity"].(string); ok {
			severityCounts[s]++
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"privesc_paths":          privescPaths,
			"path_count":             len(privescPaths),
			"unauthenticated_targets": unauthTargets,
			"summary": map[string]any{
				"total_paths":       len(privescPaths),
				"unique_roles":      len(roleSet),
				"user_pools":        len(userPools),
				"identity_pools":    len(identityPools),
				"unauth_targets":    len(unauthTargets),
				"technique_counts":  techniqueCounts,
				"severity_counts":   severityCounts,
			},
		},
	}
}

func (m *CognitoPrivescCheckModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
