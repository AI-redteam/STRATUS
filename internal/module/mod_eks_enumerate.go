package module

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stratus-framework/stratus/internal/aws"
	"github.com/stratus-framework/stratus/internal/core"
	"github.com/stratus-framework/stratus/internal/graph"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EKSEnumerateModule discovers EKS clusters, node groups, Fargate profiles,
// and identity provider configs. Identifies publicly accessible API endpoints,
// OIDC federation for IAM Roles for Service Accounts (IRSA), missing audit
// logging, node IAM roles, and Fargate execution roles.
type EKSEnumerateModule struct {
	factory *aws.ClientFactory
	graph   *graph.Store
}

func (m *EKSEnumerateModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.eks.enumerate",
		Name:        "Enumerate EKS Clusters",
		Version:     "1.0.0",
		Description: "Lists all EKS clusters with detailed configuration including API endpoint access, OIDC identity providers (IRSA), node groups with IAM roles, Fargate profiles with execution roles, VPC/subnet layout, encryption config, and logging status. Identifies clusters with public API endpoints (0.0.0.0/0), disabled audit/authenticator logging, OIDC issuers for K8s-to-AWS pivoting, node SSH access, and all IAM role ARNs for privilege escalation assessment.",
		Services:    []string{"eks"},
		RequiredActions: []string{
			"eks:ListClusters",
			"eks:DescribeCluster",
			"eks:ListNodegroups",
			"eks:DescribeNodegroup",
			"eks:ListFargateProfiles",
			"eks:DescribeFargateProfile",
			"eks:ListIdentityProviderConfigs",
			"eks:DescribeIdentityProviderConfig",
		},
		RequiredResources: []string{"arn:aws:eks:*:*:cluster/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "include_node_groups", Type: "bool", Default: true, Description: "Enumerate node groups per cluster"},
			{Name: "include_fargate", Type: "bool", Default: true, Description: "Enumerate Fargate profiles per cluster"},
			{Name: "include_identity_providers", Type: "bool", Default: true, Description: "Enumerate identity provider configs"},
			{Name: "max_clusters", Type: "int", Default: 50, Description: "Maximum clusters to enumerate"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "cluster_count", Type: "int", Description: "Total clusters found"},
			{Name: "clusters", Type: "[]map", Description: "Cluster details"},
			{Name: "iam_roles", Type: "[]string", Description: "All IAM role ARNs discovered"},
			{Name: "findings", Type: "[]map", Description: "Security findings"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1552/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EKS", SortOrder: 1},
	}
}

func (m *EKSEnumerateModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	calls := []string{"eks:ListClusters", "eks:DescribeCluster"}
	if ctx.InputBool("include_node_groups") {
		calls = append(calls, "eks:ListNodegroups", "eks:DescribeNodegroup")
	}
	if ctx.InputBool("include_fargate") {
		calls = append(calls, "eks:ListFargateProfiles", "eks:DescribeFargateProfile")
	}
	if ctx.InputBool("include_identity_providers") {
		calls = append(calls, "eks:ListIdentityProviderConfigs", "eks:DescribeIdentityProviderConfig")
	}
	return sdk.PreflightResult{PlannedAPICalls: calls, Confidence: 1.0}
}

func (m *EKSEnumerateModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate all EKS clusters with node groups, Fargate profiles, and identity provider configurations.",
		WouldMutate: false,
	}
}

func (m *EKSEnumerateModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxClusters := ctx.InputInt("max_clusters")
	if maxClusters <= 0 {
		maxClusters = 50
	}
	includeNodeGroups := ctx.InputBool("include_node_groups")
	includeFargate := ctx.InputBool("include_fargate")
	includeIdPs := ctx.InputBool("include_identity_providers")

	var findings []map[string]any
	roleSet := make(map[string]bool)

	prog.Total(4)
	prog.Update(1, "Listing EKS clusters")

	clusterNames, err := m.factory.ListEKSClusters(bgCtx, creds)
	if err != nil {
		return sdk.ErrResult(fmt.Errorf("listing EKS clusters: %w", err))
	}

	if len(clusterNames) > maxClusters {
		clusterNames = clusterNames[:maxClusters]
	}

	var clusterResults []map[string]any

	prog.Update(2, "Describing clusters")

	for _, name := range clusterNames {
		cluster, err := m.factory.DescribeEKSCluster(bgCtx, creds, name)
		if err != nil {
			clusterResults = append(clusterResults, map[string]any{
				"name":  name,
				"error": err.Error(),
			})
			continue
		}

		if cluster.RoleARN != "" {
			roleSet[cluster.RoleARN] = true
		}

		// Add graph nodes
		if m.graph != nil {
			m.graph.AddNode("eks:"+cluster.Name, "eks_cluster", cluster.Name, ctx.Session.UUID, nil)
			if cluster.RoleARN != "" {
				m.graph.AddNode("role:"+cluster.RoleARN, "iam_role", cluster.RoleARN, ctx.Session.UUID, nil)
				m.graph.AddEdge(core.GraphEdge{
					SourceNodeID: "eks:" + cluster.Name, TargetNodeID: "role:" + cluster.RoleARN,
					EdgeType: core.EdgeCanAssume, DiscoveredBySessionUUID: ctx.Session.UUID,
					DiscoveredAt: time.Now().UTC(), Confidence: 0.95,
				})
			}
		}

		entry := map[string]any{
			"name":                    cluster.Name,
			"arn":                     cluster.ARN,
			"status":                  cluster.Status,
			"version":                 cluster.Version,
			"platform_version":        cluster.PlatformVersion,
			"endpoint":                cluster.Endpoint,
			"role_arn":                cluster.RoleARN,
			"endpoint_public_access":  cluster.EndpointPublicAccess,
			"endpoint_private_access": cluster.EndpointPrivateAccess,
			"public_access_cidrs":     cluster.PublicAccessCIDRs,
			"vpc_id":                  cluster.VPCID,
			"subnet_ids":             cluster.SubnetIDs,
			"security_group_ids":     cluster.SecurityGroupIDs,
			"oidc_issuer":            cluster.OIDCIssuer,
			"logging":                cluster.Logging,
			"encryption_config":      cluster.EncryptionConfig,
			"created":                cluster.Created,
		}

		// Flag public endpoint with 0.0.0.0/0
		if cluster.EndpointPublicAccess {
			openToAll := false
			for _, cidr := range cluster.PublicAccessCIDRs {
				if cidr == "0.0.0.0/0" {
					openToAll = true
					break
				}
			}
			if openToAll {
				findings = append(findings, map[string]any{
					"resource": fmt.Sprintf("cluster/%s", cluster.Name),
					"finding":  "PublicEndpointOpenToAll",
					"severity": "high",
					"detail":   fmt.Sprintf("Cluster %s has public API endpoint accessible from 0.0.0.0/0. Any entity with valid credentials or token can interact with the Kubernetes API from the internet.", cluster.Name),
				})
			} else {
				findings = append(findings, map[string]any{
					"resource": fmt.Sprintf("cluster/%s", cluster.Name),
					"finding":  "PublicEndpoint",
					"severity": "medium",
					"detail":   fmt.Sprintf("Cluster %s has public API endpoint with restricted CIDRs: %v.", cluster.Name, cluster.PublicAccessCIDRs),
				})
			}
		}

		// Flag disabled audit logging
		auditEnabled := false
		authenticatorEnabled := false
		for _, t := range cluster.Logging.EnabledTypes {
			if t == "audit" {
				auditEnabled = true
			}
			if t == "authenticator" {
				authenticatorEnabled = true
			}
		}
		if !auditEnabled {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("cluster/%s", cluster.Name),
				"finding":  "AuditLoggingDisabled",
				"severity": "high",
				"detail":   fmt.Sprintf("Cluster %s has audit logging disabled. Kubernetes API actions (including kubectl exec, secret reads, and RBAC changes) will not be logged. Attackers can operate without detection.", cluster.Name),
			})
		}
		if !authenticatorEnabled {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("cluster/%s", cluster.Name),
				"finding":  "AuthenticatorLoggingDisabled",
				"severity": "medium",
				"detail":   fmt.Sprintf("Cluster %s has authenticator logging disabled. IAM-to-Kubernetes authentication events won't be logged, hiding credential use.", cluster.Name),
			})
		}

		// Flag OIDC for IRSA
		if cluster.OIDCIssuer != "" {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("cluster/%s", cluster.Name),
				"finding":  "OIDCProviderConfigured",
				"severity": "info",
				"detail":   fmt.Sprintf("Cluster %s has OIDC provider (%s) for IAM Roles for Service Accounts (IRSA). Kubernetes service accounts can assume AWS IAM roles. Check for overly permissive trust policies that allow any SA in the cluster.", cluster.Name, cluster.OIDCIssuer),
			})
		}

		// Flag missing encryption
		if len(cluster.EncryptionConfig) == 0 {
			findings = append(findings, map[string]any{
				"resource": fmt.Sprintf("cluster/%s", cluster.Name),
				"finding":  "NoEncryptionConfig",
				"severity": "medium",
				"detail":   fmt.Sprintf("Cluster %s has no encryption configuration. Kubernetes secrets are stored unencrypted in etcd.", cluster.Name),
			})
		}

		// Enumerate node groups
		if includeNodeGroups {
			ngNames, err := m.factory.ListEKSNodeGroups(bgCtx, creds, name)
			if err == nil && len(ngNames) > 0 {
				var nodeGroupList []map[string]any
				for _, ngName := range ngNames {
					ng, err := m.factory.DescribeEKSNodeGroup(bgCtx, creds, name, ngName)
					if err != nil {
						nodeGroupList = append(nodeGroupList, map[string]any{
							"name":  ngName,
							"error": err.Error(),
						})
						continue
					}

					if ng.NodeRoleARN != "" {
						roleSet[ng.NodeRoleARN] = true
						if m.graph != nil {
							m.graph.AddNode("role:"+ng.NodeRoleARN, "iam_role", ng.NodeRoleARN, ctx.Session.UUID, nil)
							m.graph.AddEdge(core.GraphEdge{
								SourceNodeID: "eks:" + cluster.Name, TargetNodeID: "role:" + ng.NodeRoleARN,
								EdgeType: core.EdgeCanAssume, DiscoveredBySessionUUID: ctx.Session.UUID,
								DiscoveredAt: time.Now().UTC(), Confidence: 0.90,
							})
						}
					}

					ngEntry := map[string]any{
						"name":           ng.Name,
						"status":         ng.Status,
						"node_role_arn":  ng.NodeRoleARN,
						"instance_types": ng.InstanceTypes,
						"ami_type":       ng.AMIType,
						"capacity_type":  ng.CapacityType,
						"desired_size":   ng.DesiredSize,
						"min_size":       ng.MinSize,
						"max_size":       ng.MaxSize,
					}

					if ng.RemoteAccess != nil {
						ngEntry["remote_access"] = ng.RemoteAccess
						if ng.RemoteAccess.EC2SSHKey != "" {
							findings = append(findings, map[string]any{
								"resource": fmt.Sprintf("cluster/%s/nodegroup/%s", cluster.Name, ng.Name),
								"finding":  "NodeSSHAccess",
								"severity": "medium",
								"detail":   fmt.Sprintf("Node group %s in cluster %s has SSH key %q configured. Nodes may be directly accessible for credential theft.", ng.Name, cluster.Name, ng.RemoteAccess.EC2SSHKey),
							})
						}
					}

					if ng.LaunchTemplate != nil {
						ngEntry["launch_template"] = ng.LaunchTemplate
					}

					nodeGroupList = append(nodeGroupList, ngEntry)
				}
				entry["node_groups"] = nodeGroupList
			}
		}

		// Enumerate Fargate profiles
		if includeFargate {
			fpNames, err := m.factory.ListEKSFargateProfiles(bgCtx, creds, name)
			if err == nil && len(fpNames) > 0 {
				var fargateList []map[string]any
				isFargateOnly := true // track if cluster is Fargate-only
				for _, fpName := range fpNames {
					fp, err := m.factory.DescribeEKSFargateProfile(bgCtx, creds, name, fpName)
					if err != nil {
						fargateList = append(fargateList, map[string]any{
							"name":  fpName,
							"error": err.Error(),
						})
						continue
					}

					if fp.PodExecutionRoleARN != "" {
						roleSet[fp.PodExecutionRoleARN] = true
						if m.graph != nil {
							m.graph.AddNode("role:"+fp.PodExecutionRoleARN, "iam_role", fp.PodExecutionRoleARN, ctx.Session.UUID, nil)
							m.graph.AddEdge(core.GraphEdge{
								SourceNodeID: "eks:" + cluster.Name, TargetNodeID: "role:" + fp.PodExecutionRoleARN,
								EdgeType: core.EdgeCanAssume, DiscoveredBySessionUUID: ctx.Session.UUID,
								DiscoveredAt: time.Now().UTC(), Confidence: 0.90,
							})
						}
					}

					fargateList = append(fargateList, map[string]any{
						"name":                   fp.Name,
						"status":                 fp.Status,
						"pod_execution_role_arn": fp.PodExecutionRoleARN,
						"selectors":             fp.Selectors,
					})
				}
				entry["fargate_profiles"] = fargateList

				// Check if Fargate-only (no node groups)
				if ngData, ok := entry["node_groups"]; ok {
					if ngs, ok2 := ngData.([]map[string]any); ok2 && len(ngs) > 0 {
						isFargateOnly = false
					}
				}
				if isFargateOnly && !includeNodeGroups {
					isFargateOnly = false // can't determine without node group data
				}

				if isFargateOnly {
					findings = append(findings, map[string]any{
						"resource": fmt.Sprintf("cluster/%s", cluster.Name),
						"finding":  "FargateOnlyCluster",
						"severity": "info",
						"detail":   fmt.Sprintf("Cluster %s appears Fargate-only. If the cluster creator's IAM role/user is deleted and all other admins removed from aws-auth, the cluster becomes unrecoverable (ransom scenario).", cluster.Name),
					})
				}
			}
		}

		// Enumerate identity providers
		if includeIdPs {
			idps, err := m.factory.ListEKSIdentityProviderConfigs(bgCtx, creds, name)
			if err == nil && len(idps) > 0 {
				var idpList []map[string]any
				for _, idp := range idps {
					idpList = append(idpList, map[string]any{
						"name":       idp.Name,
						"type":       idp.Type,
						"issuer_url": idp.IssuerURL,
						"client_id":  idp.ClientID,
						"status":     idp.Status,
					})
				}
				entry["identity_providers"] = idpList
			}
		}

		clusterResults = append(clusterResults, entry)
	}

	prog.Update(4, "Analysis complete")

	var roles []string
	for r := range roleSet {
		roles = append(roles, r)
	}

	// Extract account ID from role ARNs for summary
	accountID := ""
	for _, r := range roles {
		parts := strings.SplitN(r, ":", 6)
		if len(parts) >= 5 {
			accountID = parts[4]
			break
		}
	}
	_ = accountID

	return sdk.RunResult{
		Outputs: map[string]any{
			"cluster_count": len(clusterResults),
			"clusters":      clusterResults,
			"iam_roles":     roles,
			"findings":      findings,
		},
	}
}

func (m *EKSEnumerateModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
