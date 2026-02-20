package module

import (
	"context"
	"fmt"
	"strings"

	"github.com/stratus-framework/stratus/internal/aws"
	sdk "github.com/stratus-framework/stratus/pkg/sdk/v1"
)

// EKSPrivescCheckModule identifies EKS privilege escalation paths based on
// techniques documented in hacktricks-cloud. Covers AWS-side attacks (cluster
// role assumption, node role theft, Fargate execution role pivoting, OIDC/IRSA
// abuse, aws-auth configmap manipulation) and Kubernetes-side attacks (pod
// creation with hostNetwork/privileged, IMDS credential theft, service account
// token harvesting).
type EKSPrivescCheckModule struct {
	factory *aws.ClientFactory
}

func (m *EKSPrivescCheckModule) Meta() sdk.ModuleMeta {
	return sdk.ModuleMeta{
		ID:          "com.stratus.eks.privesc-check",
		Name:        "EKS Privilege Escalation Check",
		Version:     "1.0.0",
		Description: "Identifies EKS privilege escalation paths across both the AWS and Kubernetes layers. AWS-side: cluster role assumption, node IAM role theft via IMDS, Fargate execution role pivoting, OIDC/IRSA abuse for K8s-to-AWS credential access, and aws-auth configmap manipulation for cluster takeover. K8s-side: privileged pod creation for node escape, hostNetwork pods for metadata service access, service account token theft, DaemonSet deployment for cluster-wide credential harvesting, and static pod persistence. Also detects CloudTrail evasion via manual kubeconfig.",
		Services:    []string{"eks"},
		RequiredActions: []string{
			"eks:ListClusters",
			"eks:DescribeCluster",
			"eks:ListNodegroups",
			"eks:DescribeNodegroup",
			"eks:ListFargateProfiles",
			"eks:DescribeFargateProfile",
		},
		RequiredResources: []string{"arn:aws:eks:*:*:cluster/*"},
		RiskClass:         sdk.RiskReadOnly,
		Inputs: []sdk.InputSpec{
			{Name: "max_clusters", Type: "int", Default: 50, Description: "Maximum clusters to analyze"},
		},
		Outputs: []sdk.OutputSpec{
			{Name: "privesc_paths", Type: "[]map", Description: "Identified privilege escalation paths"},
			{Name: "path_count", Type: "int", Description: "Total escalation paths found"},
			{Name: "target_roles", Type: "[]map", Description: "IAM roles that can be targeted"},
			{Name: "summary", Type: "map", Description: "Aggregate summary"},
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1078.004/",
			"https://attack.mitre.org/techniques/T1552/",
			"https://attack.mitre.org/techniques/T1610/",
			"https://attack.mitre.org/techniques/T1611/",
		},
		Author:  "STRATUS Core",
		UIHints: sdk.UIHintSpec{Category: "EKS", SortOrder: 2},
	}
}

func (m *EKSPrivescCheckModule) Preflight(ctx sdk.RunContext) sdk.PreflightResult {
	return sdk.PreflightResult{
		PlannedAPICalls: []string{
			"eks:ListClusters", "eks:DescribeCluster",
			"eks:ListNodegroups", "eks:DescribeNodegroup",
			"eks:ListFargateProfiles", "eks:DescribeFargateProfile",
		},
		Confidence: 1.0,
	}
}

func (m *EKSPrivescCheckModule) DryRun(ctx sdk.RunContext) sdk.DryRunResult {
	return sdk.DryRunResult{
		Description: "Would enumerate EKS clusters, node groups, and Fargate profiles to identify AWS and Kubernetes privilege escalation paths.",
		WouldMutate: false,
	}
}

func (m *EKSPrivescCheckModule) Run(ctx sdk.RunContext, prog sdk.Progress) sdk.RunResult {
	creds := aws.SessionCredentials{Region: ctx.Session.Region}
	bgCtx := context.Background()

	maxClusters := ctx.InputInt("max_clusters")
	if maxClusters <= 0 {
		maxClusters = 50
	}

	var privescPaths []map[string]any
	var targetRoles []map[string]any
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

	if len(clusterNames) == 0 {
		return sdk.RunResult{
			Outputs: map[string]any{
				"privesc_paths": []map[string]any{},
				"path_count":    0,
				"target_roles":  []map[string]any{},
				"summary":       map[string]any{"total_paths": 0, "total_clusters": 0},
			},
		}
	}

	prog.Update(2, "Analyzing cluster configurations")

	for _, name := range clusterNames {
		cluster, err := m.factory.DescribeEKSCluster(bgCtx, creds, name)
		if err != nil {
			continue
		}

		if cluster.RoleARN != "" && !roleSet[cluster.RoleARN] {
			roleSet[cluster.RoleARN] = true
			roleName := cluster.RoleARN
			if idx := strings.LastIndex(cluster.RoleARN, "/"); idx >= 0 {
				roleName = cluster.RoleARN[idx+1:]
			}
			targetRoles = append(targetRoles, map[string]any{
				"role_arn":  cluster.RoleARN,
				"role_name": roleName,
				"resource":  cluster.Name,
				"type":      "cluster_role",
			})
		}

		// --- AWS-side techniques ---

		// Technique 1: aws-auth configmap manipulation
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "AwsAuthConfigmapTakeover",
			"severity":    "critical",
			"resource":    cluster.Name,
			"layer":       "kubernetes",
			"description": fmt.Sprintf("With kubectl write access to the aws-auth ConfigMap in kube-system namespace of cluster %s, an attacker can add any IAM role/user with system:masters group, granting full cluster-admin. Can also grant cross-account access.", cluster.Name),
			"required_permissions": []string{"(K8s: update configmaps in kube-system)"},
		})

		// Technique 2: Cluster creator permanent admin
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "ClusterCreatorAdmin",
			"severity":    "high",
			"resource":    cluster.Name,
			"layer":       "aws",
			"description": fmt.Sprintf("The IAM principal that created cluster %s has irremovable system:masters access. If the creator's credentials are compromised, the cluster is fully compromised. Check CloudTrail for CreateCluster events.", cluster.Name),
			"required_permissions": []string{"(access to cluster creator IAM credentials)"},
		})

		// Technique 3: OIDC/IRSA abuse — K8s to AWS pivoting
		if cluster.OIDCIssuer != "" {
			privescPaths = append(privescPaths, map[string]any{
				"technique":   "IRSARoleAssumption",
				"severity":    "high",
				"resource":    cluster.Name,
				"target_role": "(IRSA-mapped roles)",
				"layer":       "kubernetes",
				"description": fmt.Sprintf("Cluster %s has OIDC provider (%s) for IRSA. Service accounts annotated with eks.amazonaws.com/role-arn can assume AWS IAM roles. Create pods with annotated SAs or read the web identity token at /var/run/secrets/eks.amazonaws.com/serviceaccount/token to call sts:AssumeRoleWithWebIdentity. Misconfigured trust policies may allow any SA in the cluster.", cluster.Name, cluster.OIDCIssuer),
				"required_permissions": []string{"(K8s: create pods or read SA tokens)"},
			})
		}

		// Technique 4: CloudTrail evasion
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "CloudTrailEvasion",
			"severity":    "medium",
			"resource":    cluster.Name,
			"layer":       "aws",
			"description": fmt.Sprintf("Using manual kubeconfig with eks get-token for cluster %s avoids CloudTrail logging for the token generation. If audit logging is disabled on the cluster, K8s API calls are also invisible.", cluster.Name),
			"required_permissions": []string{"eks:DescribeCluster (optional)"},
		})

		// Technique 5: Public endpoint exploitation
		if cluster.EndpointPublicAccess {
			openToAll := false
			for _, cidr := range cluster.PublicAccessCIDRs {
				if cidr == "0.0.0.0/0" {
					openToAll = true
					break
				}
			}
			if openToAll {
				privescPaths = append(privescPaths, map[string]any{
					"technique":   "PublicEndpointAccess",
					"severity":    "high",
					"resource":    cluster.Name,
					"endpoint":    cluster.Endpoint,
					"layer":       "network",
					"description": fmt.Sprintf("Cluster %s API endpoint %s is publicly accessible from 0.0.0.0/0. Any valid token (from get-token or stolen SA token) can be used remotely without VPC access.", cluster.Name, cluster.Endpoint),
					"required_permissions": []string{"(valid K8s token or IAM credentials)"},
				})
			}
		}

		// --- K8s-side techniques ---

		// Technique 6: Privileged pod creation for node escape
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "PrivilegedPodEscape",
			"severity":    "critical",
			"resource":    cluster.Name,
			"layer":       "kubernetes",
			"description": fmt.Sprintf("With pod creation privileges in cluster %s, create a pod with hostPID, hostNetwork, privileged securityContext, and hostPath mount to /. Use nsenter --target 1 --mount to escape to the node, then steal all SA tokens, access IMDS, and read kubelet credentials.", cluster.Name),
			"required_permissions": []string{"(K8s: create pods)"},
		})

		// Technique 7: hostNetwork pod for IMDS credential theft
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "IMDSCredentialTheft",
			"severity":    "high",
			"resource":    cluster.Name,
			"layer":       "kubernetes",
			"description": fmt.Sprintf("Create a pod with hostNetwork: true in cluster %s to access the EC2 instance metadata service at 169.254.169.254 and steal the node IAM role credentials.", cluster.Name),
			"required_permissions": []string{"(K8s: create pods with hostNetwork)"},
		})

		// Technique 8: DaemonSet for cluster-wide token theft
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "DaemonSetTokenHarvest",
			"severity":    "critical",
			"resource":    cluster.Name,
			"layer":       "kubernetes",
			"description": fmt.Sprintf("Deploy a DaemonSet in cluster %s with a privileged SA and hostPath mount to harvest service account tokens from all nodes. Tokens are stored at /var/run/secrets/kubernetes.io/serviceaccount/ in each pod's tmpfs.", cluster.Name),
			"required_permissions": []string{"(K8s: create daemonsets)"},
		})

		// Technique 9: Service account token creation
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "SATokenCreation",
			"severity":    "high",
			"resource":    cluster.Name,
			"layer":       "kubernetes",
			"description": fmt.Sprintf("With access to create tokens or secrets in cluster %s, generate long-lived SA tokens for privileged service accounts (e.g., bootstrap-signer, cluster-admin). Create a Secret of type kubernetes.io/service-account-token referencing the target SA.", cluster.Name),
			"required_permissions": []string{"(K8s: create secrets or serviceaccounts/token)"},
		})

		// Technique 10: Static pod persistence
		privescPaths = append(privescPaths, map[string]any{
			"technique":   "StaticPodPersistence",
			"severity":    "high",
			"resource":    cluster.Name,
			"layer":       "kubernetes",
			"description": fmt.Sprintf("After escaping to a node in cluster %s, place pod manifests in /etc/kubernetes/manifests/ for automatic execution by kubelet. These pods are invisible to the API server and survive cluster-level cleanup.", cluster.Name),
			"required_permissions": []string{"(node-level filesystem access)"},
		})

		// --- Enumerate node groups for role targets ---
		ngNames, err := m.factory.ListEKSNodeGroups(bgCtx, creds, name)
		if err == nil {
			for _, ngName := range ngNames {
				ng, err := m.factory.DescribeEKSNodeGroup(bgCtx, creds, name, ngName)
				if err != nil {
					continue
				}

				if ng.NodeRoleARN != "" && !roleSet[ng.NodeRoleARN] {
					roleSet[ng.NodeRoleARN] = true
					roleName := ng.NodeRoleARN
					if idx := strings.LastIndex(ng.NodeRoleARN, "/"); idx >= 0 {
						roleName = ng.NodeRoleARN[idx+1:]
					}
					targetRoles = append(targetRoles, map[string]any{
						"role_arn":  ng.NodeRoleARN,
						"role_name": roleName,
						"resource":  fmt.Sprintf("%s/%s", name, ng.Name),
						"type":      "node_role",
					})
				}

				// Technique 11: Node IAM role theft for this specific node group
				privescPaths = append(privescPaths, map[string]any{
					"technique":   "NodeRoleTheft",
					"severity":    "high",
					"resource":    fmt.Sprintf("%s/%s", name, ng.Name),
					"target_role": ng.NodeRoleARN,
					"layer":       "kubernetes",
					"description": fmt.Sprintf("Node group %s in cluster %s uses IAM role %s. From a pod on these nodes, access http://169.254.169.254/latest/meta-data/iam/security-credentials/ to steal node credentials. The node role typically has permissions for ECR, EBS, ELB, and sometimes broader access.", ng.Name, name, ng.NodeRoleARN),
					"required_permissions": []string{"(pod with hostNetwork or IMDS hop limit > 1)"},
				})

				// Technique 12: Node SSH access
				if ng.RemoteAccess != nil && ng.RemoteAccess.EC2SSHKey != "" {
					privescPaths = append(privescPaths, map[string]any{
						"technique":   "NodeSSHAccess",
						"severity":    "medium",
						"resource":    fmt.Sprintf("%s/%s", name, ng.Name),
						"target_role": ng.NodeRoleARN,
						"layer":       "network",
						"description": fmt.Sprintf("Node group %s has SSH key %q. Direct SSH to nodes bypasses Kubernetes RBAC entirely and grants access to the node IAM role, kubelet credentials, and all pod SA tokens.", ng.Name, ng.RemoteAccess.EC2SSHKey),
						"required_permissions": []string{"(SSH key + network access)"},
					})
				}
			}
		}

		// --- Enumerate Fargate profiles for role targets ---
		fpNames, err := m.factory.ListEKSFargateProfiles(bgCtx, creds, name)
		if err == nil {
			fargateOnly := len(ngNames) == 0 && len(fpNames) > 0
			for _, fpName := range fpNames {
				fp, err := m.factory.DescribeEKSFargateProfile(bgCtx, creds, name, fpName)
				if err != nil {
					continue
				}

				if fp.PodExecutionRoleARN != "" && !roleSet[fp.PodExecutionRoleARN] {
					roleSet[fp.PodExecutionRoleARN] = true
					roleName := fp.PodExecutionRoleARN
					if idx := strings.LastIndex(fp.PodExecutionRoleARN, "/"); idx >= 0 {
						roleName = fp.PodExecutionRoleARN[idx+1:]
					}
					targetRoles = append(targetRoles, map[string]any{
						"role_arn":  fp.PodExecutionRoleARN,
						"role_name": roleName,
						"resource":  fmt.Sprintf("%s/%s", name, fp.Name),
						"type":      "fargate_execution_role",
					})
				}
			}

			// Technique 13: Fargate ransom scenario
			if fargateOnly {
				privescPaths = append(privescPaths, map[string]any{
					"technique":   "FargateRansom",
					"severity":    "medium",
					"resource":    name,
					"layer":       "aws",
					"description": fmt.Sprintf("Cluster %s is Fargate-only (no EC2 node groups). If the cluster creator's IAM identity is deleted and all admins removed from aws-auth, the cluster becomes permanently inaccessible — a ransom scenario with no recovery path.", name),
					"required_permissions": []string{"(cluster admin + IAM delete)"},
				})
			}
		}
	}

	prog.Update(3, "Adding general techniques")

	// Technique 14: Impersonation
	privescPaths = append(privescPaths, map[string]any{
		"technique":   "K8sImpersonation",
		"severity":    "critical",
		"resource":    "(all clusters)",
		"layer":       "kubernetes",
		"description": "With impersonate verb on users/groups/serviceaccounts, bypass RBAC by impersonating system:masters group: kubectl get secrets --as=null --as-group=system:masters. Check ClusterRoleBindings for impersonate permissions.",
		"required_permissions": []string{"(K8s: impersonate verb)"},
	})

	// Technique 15: Webhook admission controller manipulation
	privescPaths = append(privescPaths, map[string]any{
		"technique":   "WebhookManipulation",
		"severity":    "critical",
		"resource":    "(all clusters)",
		"layer":       "kubernetes",
		"description": "With create/update on ValidatingWebhookConfiguration or MutatingWebhookConfiguration, intercept and modify all API requests. MutatingWebhooks can inject sidecar containers, modify pod specs, or alter RBAC objects.",
		"required_permissions": []string{"(K8s: create/update webhookconfigurations)"},
	})

	// Technique 16: CoreDNS poisoning
	privescPaths = append(privescPaths, map[string]any{
		"technique":   "CoreDNSPoisoning",
		"severity":    "high",
		"resource":    "(all clusters)",
		"layer":       "kubernetes",
		"description": "With write access to the coredns ConfigMap in kube-system, add rewrite rules to redirect DNS queries cluster-wide. Enables credential interception, traffic hijacking, and service impersonation.",
		"required_permissions": []string{"(K8s: update configmaps in kube-system)"},
	})

	prog.Update(4, "Building summary")

	techniqueCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	layerCounts := make(map[string]int)
	for _, p := range privescPaths {
		if t, ok := p["technique"].(string); ok {
			techniqueCounts[t]++
		}
		if s, ok := p["severity"].(string); ok {
			severityCounts[s]++
		}
		if l, ok := p["layer"].(string); ok {
			layerCounts[l]++
		}
	}

	return sdk.RunResult{
		Outputs: map[string]any{
			"privesc_paths": privescPaths,
			"path_count":    len(privescPaths),
			"target_roles":  targetRoles,
			"summary": map[string]any{
				"total_paths":      len(privescPaths),
				"total_clusters":   len(clusterNames),
				"unique_roles":     len(roleSet),
				"technique_counts": techniqueCounts,
				"severity_counts":  severityCounts,
				"layer_counts":     layerCounts,
			},
		},
	}
}

func (m *EKSPrivescCheckModule) Replay(ctx sdk.RunContext, prior sdk.PriorRunRecord) sdk.RunResult {
	return m.Run(ctx, sdk.NoOpProgress)
}
