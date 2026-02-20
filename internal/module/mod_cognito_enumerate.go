package module

import (
	"context"
	"fmt"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// CognitoEnumerateModule discovers Cognito User Pools and Identity Pools.
// Enumerates pool configurations, clients, groups with IAM roles, identity
// providers, and identity pool role mappings. Identifies pools with
// unauthenticated access, self-registration, weak MFA, and classic auth flow.
type CognitoEnumerateModule struct {
	factory *aws.ClientFactory
}

func (m *CognitoEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.cognito.enumerate",
		Name:        "Enumerate Cognito Pools",
		Version:     "1.0.0",
		Description: "Enumerates Cognito User Pools (with clients, groups, identity providers, MFA config) and Identity Pools (with role mappings, unauthenticated access, classic flow). Identifies pools with self-registration enabled, no MFA, unauthenticated IAM role access, basic/classic auth flow (bypasses session policy restrictions), groups with IAM roles (role escalation targets), and external identity providers.",
		Services:    []string{"cognito-idp", "cognito-identity"},
		RequiredActions: []string{
			"cognito-idp:ListUserPools",
			"cognito-idp:DescribeUserPool",
			"cognito-idp:ListUserPoolClients",
			"cognito-idp:ListGroups",
			"cognito-idp:ListIdentityProviders",
			"cognito-identity:ListIdentityPools",
			"cognito-identity:DescribeIdentityPool",
			"cognito-identity:GetIdentityPoolRoles",
		},
		RequiredResources: []string{"*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "include_user_pools", Type: "bool", Default: true, Description: "Enumerate User Pools with clients, groups, and IdPs"},
			{Name: "include_identity_pools", Type: "bool", Default: true, Description: "Enumerate Identity Pools with role mappings"},
			{Name: "max_pools", Type: "int", Default: 60, Description: "Maximum pools per type to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "user_pools", Type: "[]map", Description: "User Pool details"},
			{Name: "identity_pools", Type: "[]map", Description: "Identity Pool details with role mappings"},
			{Name: "groups_with_roles", Type: "[]map", Description: "User Pool groups with IAM roles attached"},
			{Name: "iam_roles", Type: "[]string", Description: "All IAM role ARNs discovered"},
			{Name: "findings", Type: "[]map", Description: "Security findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1136/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "Cognito", SortOrder: 1},
	}
}

func (m *CognitoEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	var calls []string
	if ctx.InputBool("include_user_pools") {
		calls = append(calls, "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
			"cognito-idp:ListUserPoolClients", "cognito-idp:ListGroups", "cognito-idp:ListIdentityProviders")
	}
	if ctx.InputBool("include_identity_pools") {
		calls = append(calls, "cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
			"cognito-identity:GetIdentityPoolRoles")
	}
	return sdk.PreflightResult{PlannedAPICalls: calls, Confidence: 1.0}
}

func (m *CognitoEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate Cognito User Pools and Identity Pools with their configurations, clients, groups, identity providers, and IAM role mappings.",
		WouldMutate: false,
	}
}

func (m *CognitoEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxPools := ctx.InputInt("max_pools")
	if maxPools <= 0 {
		maxPools = 60
	}

	var findings []map[string]any
	var userPoolResults []map[string]any
	var identityPoolResults []map[string]any
	var groupsWithRoles []map[string]any
	roleSet := make(map[string]bool)

	steps := 0
	if ctx.InputBool("include_user_pools") {
		steps += 2
	}
	if ctx.InputBool("include_identity_pools") {
		steps += 2
	}
	prog.Total(steps)
	step := 0

	// --- User Pools ---
	if ctx.InputBool("include_user_pools") {
		step++
		prog.Update(step, "Listing User Pools")

		userPools, err := m.factory.ListCognitoUserPools(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "user_pools", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list user pools: %v", err),
			})
		} else {
			step++
			prog.Update(step, "Describing User Pools")

			for i, pool := range userPools {
				if i >= maxPools {
					break
				}

				detail, err := m.factory.DescribeCognitoUserPool(bgCtx, creds, pool.PoolID)
				if err != nil {
					userPoolResults = append(userPoolResults, map[string]any{
						"pool_id":   pool.PoolID,
						"pool_name": pool.PoolName,
						"status":    pool.Status,
					})
					continue
				}

				entry := map[string]any{
					"pool_id":              detail.PoolID,
					"pool_name":            detail.PoolName,
					"arn":                  detail.ARN,
					"status":               detail.Status,
					"mfa_configuration":    detail.MFAConfiguration,
					"estimated_users":      detail.EstimatedUsers,
					"self_signup_enabled":  detail.SelfSignUpEnabled,
					"deletion_protection":  detail.DeletionProtection,
					"domain":               detail.Domain,
					"custom_domain":        detail.CustomDomain,
				}

				// Flag self-registration
				if detail.SelfSignUpEnabled {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("user_pool/%s", detail.PoolID),
						"finding":  "SelfSignUpEnabled",
						"severity": "high",
						"detail":   fmt.Sprintf("User Pool %s (%s) allows self-registration. Anyone with the Client ID can create accounts and potentially obtain authenticated IAM roles.", detail.PoolName, detail.PoolID),
					})
				}

				// Flag weak MFA
				if detail.MFAConfiguration == "OFF" {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("user_pool/%s", detail.PoolID),
						"finding":  "MFADisabled",
						"severity": "medium",
						"detail":   fmt.Sprintf("User Pool %s has MFA disabled. Accounts are vulnerable to credential stuffing and brute force.", detail.PoolName),
					})
				}

				// Enumerate clients
				clients, err := m.factory.ListCognitoUserPoolClients(bgCtx, creds, pool.PoolID)
				if err == nil && len(clients) > 0 {
					var clientList []map[string]any
					for _, c := range clients {
						clientList = append(clientList, map[string]any{
							"client_id":   c.ClientID,
							"client_name": c.ClientName,
						})
					}
					entry["clients"] = clientList
				}

				// Enumerate groups — identify those with IAM roles
				groups, err := m.factory.ListCognitoGroups(bgCtx, creds, pool.PoolID)
				if err == nil && len(groups) > 0 {
					var groupList []map[string]any
					for _, g := range groups {
						ge := map[string]any{
							"group_name":  g.GroupName,
							"description": g.Description,
							"precedence":  g.Precedence,
						}
						if g.RoleARN != "" {
							ge["role_arn"] = g.RoleARN
							roleSet[g.RoleARN] = true
							groupsWithRoles = append(groupsWithRoles, map[string]any{
								"pool_id":    pool.PoolID,
								"pool_name":  pool.PoolName,
								"group_name": g.GroupName,
								"role_arn":   g.RoleARN,
							})
						}
						groupList = append(groupList, ge)
					}
					entry["groups"] = groupList
				}

				// Enumerate identity providers
				idps, err := m.factory.ListCognitoIdentityProviders(bgCtx, creds, pool.PoolID)
				if err == nil && len(idps) > 0 {
					var idpList []map[string]any
					for _, idp := range idps {
						idpList = append(idpList, map[string]any{
							"provider_name": idp.ProviderName,
							"provider_type": idp.ProviderType,
							"created":       idp.Created,
						})
					}
					entry["identity_providers"] = idpList

					if len(idps) > 0 {
						findings = append(findings, map[string]any{
							"resource": fmt.Sprintf("user_pool/%s", detail.PoolID),
							"finding":  "ExternalIdPConfigured",
							"severity": "info",
							"detail":   fmt.Sprintf("User Pool %s has %d external identity providers. These could be manipulated via cognito-idp:CreateIdentityProvider or UpdateIdentityProvider for persistence.", detail.PoolName, len(idps)),
						})
					}
				}

				userPoolResults = append(userPoolResults, entry)
			}
		}
	}

	// --- Identity Pools ---
	if ctx.InputBool("include_identity_pools") {
		step++
		prog.Update(step, "Listing Identity Pools")

		identityPools, err := m.factory.ListCognitoIdentityPools(bgCtx, creds)
		if err != nil {
			findings = append(findings, map[string]any{
				"resource": "identity_pools", "finding": "ListFailed", "severity": "info",
				"detail": fmt.Sprintf("could not list identity pools: %v", err),
			})
		} else {
			step++
			prog.Update(step, "Describing Identity Pools")

			for i, pool := range identityPools {
				if i >= maxPools {
					break
				}

				detail, err := m.factory.DescribeCognitoIdentityPool(bgCtx, creds, pool.PoolID)
				if err != nil {
					identityPoolResults = append(identityPoolResults, map[string]any{
						"pool_id":   pool.PoolID,
						"pool_name": pool.PoolName,
					})
					continue
				}

				entry := map[string]any{
					"pool_id":                pool.PoolID,
					"pool_name":              pool.PoolName,
					"allow_unauthenticated":  detail.AllowUnauthenticated,
					"allow_classic_flow":     detail.AllowClassicFlow,
					"cognito_providers":      detail.CognitoIdentityProviders,
					"supported_logins":       detail.SupportedLoginProviders,
					"openid_providers":       detail.OpenIDConnectProviderARNs,
					"saml_providers":         detail.SAMLProviderARNs,
				}

				// Get role mappings
				roles, err := m.factory.GetCognitoIdentityPoolRoles(bgCtx, creds, pool.PoolID)
				if err == nil {
					entry["authenticated_role"] = roles.AuthenticatedRole
					entry["unauthenticated_role"] = roles.UnauthenticatedRole
					entry["role_mappings"] = roles.RoleMappings

					if roles.AuthenticatedRole != "" {
						roleSet[roles.AuthenticatedRole] = true
					}
					if roles.UnauthenticatedRole != "" {
						roleSet[roles.UnauthenticatedRole] = true
					}
				}

				// Flag unauthenticated access
				if detail.AllowUnauthenticated {
					severity := "high"
					desc := fmt.Sprintf("Identity Pool %s (%s) allows unauthenticated access. Anyone with the Pool ID can obtain temporary IAM credentials.", pool.PoolName, pool.PoolID)
					if roles != nil && roles.UnauthenticatedRole != "" {
						desc += fmt.Sprintf(" Unauthenticated role: %s.", roles.UnauthenticatedRole)
					}
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("identity_pool/%s", pool.PoolID),
						"finding":  "UnauthenticatedAccess",
						"severity": severity,
						"detail":   desc,
					})
				}

				// Flag classic/basic flow
				if detail.AllowClassicFlow {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("identity_pool/%s", pool.PoolID),
						"finding":  "ClassicFlowEnabled",
						"severity": "high",
						"detail":   fmt.Sprintf("Identity Pool %s has Basic (Classic) auth flow enabled. This bypasses the enhanced flow session policy restrictions, granting unrestricted access to the mapped IAM role.", pool.PoolName),
					})
				}

				// Flag unauthenticated + classic flow combination
				if detail.AllowUnauthenticated && detail.AllowClassicFlow {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("identity_pool/%s", pool.PoolID),
						"finding":  "UnauthClassicCombo",
						"severity": "critical",
						"detail":   fmt.Sprintf("Identity Pool %s allows BOTH unauthenticated access AND classic flow. An unauthenticated user can obtain unrestricted IAM credentials with the full permissions of the unauthenticated role.", pool.PoolName),
					})
				}

				identityPoolResults = append(identityPoolResults, entry)
			}
		}
	}

	var roles []string
	for r := range roleSet {
		roles = append(roles, r)
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"user_pools":       userPoolResults,
			"identity_pools":   identityPoolResults,
			"groups_with_roles": groupsWithRoles,
			"iam_roles":        roles,
			"findings":         findings,
		},
	}
}

func (m *CognitoEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
