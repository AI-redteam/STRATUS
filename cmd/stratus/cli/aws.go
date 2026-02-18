package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	awsops "github.com/stratus-framework/stratus/internal/aws"
)

// RegisterAWSCommands adds the `stratus aws` service command tree.
func RegisterAWSCommands(root *cobra.Command) {
	awsCmd := &cobra.Command{
		Use:   "aws",
		Short: "AWS service enumeration and operations",
		Long: `Query AWS services using the active session credentials.
All commands are read-only unless explicitly stated.
Results are cached in-memory (5 min TTL) to reduce API noise.`,
	}

	awsCmd.AddCommand(newAWSIAMCmd())
	awsCmd.AddCommand(newAWSS3Cmd())
	awsCmd.AddCommand(newAWSEC2Cmd())
	awsCmd.AddCommand(newAWSLambdaCmd())
	awsCmd.AddCommand(newAWSSecretsCmd())
	awsCmd.AddCommand(newAWSSSMCmd())
	awsCmd.AddCommand(newAWSCloudTrailCmd())
	awsCmd.AddCommand(newAWSKMSCmd())
	awsCmd.AddCommand(newAWSLogsCmd())
	awsCmd.AddCommand(newAWSWhoamiCmd())
	awsCmd.AddCommand(newAWSRegionsCmd())
	awsCmd.AddCommand(newAWSCacheClearCmd())

	root.AddCommand(awsCmd)
}

// --- credential + factory helper ---

func awsClientSetup() (*awsops.ClientFactory, awsops.SessionCredentials, func(), error) {
	engine, err := loadActiveEngine()
	if err != nil {
		return nil, awsops.SessionCredentials{}, nil, err
	}
	cleanup := func() { engine.Close() }

	creds, sess, err := awsops.ResolveActiveCredentials(engine)
	if err != nil {
		cleanup()
		return nil, awsops.SessionCredentials{}, nil, err
	}

	factory := awsops.NewClientFactoryWithAudit(engine.Logger, engine.AuditLogger, sess.UUID)
	return factory, creds, cleanup, nil
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

// ---- whoami ----

func newAWSWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the current STS caller identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			arn, account, userID, err := factory.GetCallerIdentity(context.Background(), creds)
			if err != nil {
				return err
			}

			fmt.Printf("Account:  %s\n", account)
			fmt.Printf("ARN:      %s\n", arn)
			fmt.Printf("UserID:   %s\n", userID)
			return nil
		},
	}
}

// ---- regions ----

func newAWSRegionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "regions",
		Short: "List available AWS regions",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			regions, err := factory.ListRegions(context.Background(), creds)
			if err != nil {
				return err
			}
			for _, r := range regions {
				fmt.Println(r)
			}
			return nil
		},
	}
}

// ---- cache clear ----

func newAWSCacheClearCmd() *cobra.Command {
	var prefix string
	cmd := &cobra.Command{
		Use:   "cache-clear",
		Short: "Clear the in-memory response cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, _, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			n := factory.Cache().Clear(prefix)
			fmt.Printf("Cleared %d cached entries.\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "", "Only clear entries matching this key prefix (e.g. 'iam:', 's3:')")
	return cmd
}

// ============================ IAM ============================

func newAWSIAMCmd() *cobra.Command {
	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "IAM enumeration (users, roles, policies)",
	}
	iamCmd.AddCommand(newIAMUsersCmd())
	iamCmd.AddCommand(newIAMRolesCmd())
	iamCmd.AddCommand(newIAMPoliciesCmd())
	iamCmd.AddCommand(newIAMUserDetailCmd())
	iamCmd.AddCommand(newIAMRoleDetailCmd())
	return iamCmd
}

func newIAMUsersCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "users",
		Short: "List IAM users",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			users, err := factory.ListIAMUsers(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(users)
				return nil
			}
			if len(users) == 0 {
				fmt.Println("No IAM users found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "USER NAME\tUSER ID\tARN\tCREATED")
			for _, u := range users {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.UserName, u.UserID, u.ARN, u.CreateDate)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newIAMRolesCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "List IAM roles",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			roles, err := factory.ListIAMRoles(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(roles)
				return nil
			}
			if len(roles) == 0 {
				fmt.Println("No IAM roles found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ROLE NAME\tROLE ID\tARN\tCREATED")
			for _, r := range roles {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.RoleName, r.RoleID, r.ARN, r.CreateDate)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newIAMPoliciesCmd() *cobra.Command {
	var asJSON bool
	var attached bool
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "List IAM policies (customer-managed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			policies, err := factory.ListIAMPolicies(context.Background(), creds, attached)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(policies)
				return nil
			}
			if len(policies) == 0 {
				fmt.Println("No IAM policies found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "POLICY NAME\tPOLICY ID\tARN\tATTACHED")
			for _, p := range policies {
				fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", p.PolicyName, p.PolicyID, p.ARN, p.IsAttached)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&attached, "attached-only", false, "Only show policies attached to at least one entity")
	return cmd
}

func newIAMUserDetailCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "user-details <username>",
		Short: "Show detailed info for an IAM user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			detail, err := factory.GetIAMUserDetail(context.Background(), creds, args[0])
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(detail)
				return nil
			}

			fmt.Printf("User: %s\n", detail.UserName)
			fmt.Printf("  ARN:      %s\n", detail.ARN)
			fmt.Printf("  User ID:  %s\n", detail.UserID)
			fmt.Printf("  Created:  %s\n", detail.CreateDate)
			printList("  Groups", detail.Groups)
			printList("  Attached Policies", detail.AttachedPolicies)
			printList("  Inline Policies", detail.InlinePolicies)
			printList("  Access Keys", detail.AccessKeys)
			printList("  MFA Devices", detail.MFADevices)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newIAMRoleDetailCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "role-details <rolename>",
		Short: "Show detailed info for an IAM role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			detail, err := factory.GetIAMRoleDetail(context.Background(), creds, args[0])
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(detail)
				return nil
			}

			fmt.Printf("Role: %s\n", detail.RoleName)
			fmt.Printf("  ARN:     %s\n", detail.ARN)
			fmt.Printf("  Role ID: %s\n", detail.RoleID)
			fmt.Printf("  Created: %s\n", detail.CreateDate)
			fmt.Printf("  Trust Policy:\n    %s\n", detail.AssumeRolePolicyDoc)
			printList("  Attached Policies", detail.AttachedPolicies)
			printList("  Inline Policies", detail.InlinePolicies)
			printList("  Instance Profiles", detail.InstanceProfileARNs)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ============================ S3 ============================

func newAWSS3Cmd() *cobra.Command {
	s3Cmd := &cobra.Command{
		Use:   "s3",
		Short: "S3 enumeration (buckets, policies, objects)",
	}
	s3Cmd.AddCommand(newS3BucketsCmd())
	s3Cmd.AddCommand(newS3BucketPolicyCmd())
	s3Cmd.AddCommand(newS3LsCmd())
	return s3Cmd
}

func newS3BucketsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "buckets",
		Short: "List S3 buckets",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			buckets, err := factory.ListS3Buckets(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(buckets)
				return nil
			}
			if len(buckets) == 0 {
				fmt.Println("No S3 buckets found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "BUCKET\tCREATED")
			for _, b := range buckets {
				fmt.Fprintf(w, "%s\t%s\n", b.Name, b.CreationDate)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newS3BucketPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bucket-policy <bucket-name>",
		Short: "Retrieve the bucket policy JSON for a bucket",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			policy, err := factory.GetBucketPolicy(context.Background(), creds, args[0])
			if err != nil {
				return err
			}

			// Pretty-print JSON
			var parsed any
			if json.Unmarshal([]byte(policy), &parsed) == nil {
				pretty, _ := json.MarshalIndent(parsed, "", "  ")
				fmt.Println(string(pretty))
			} else {
				fmt.Println(policy)
			}
			return nil
		},
	}
	return cmd
}

func newS3LsCmd() *cobra.Command {
	var prefix string
	var maxKeys int32
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ls <bucket-name>",
		Short: "List objects in an S3 bucket",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			objects, err := factory.ListS3Objects(context.Background(), creds, args[0], prefix, maxKeys)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(objects)
				return nil
			}
			if len(objects) == 0 {
				fmt.Println("No objects found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tSIZE\tLAST MODIFIED\tCLASS")
			for _, o := range objects {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", o.Key, o.Size, o.LastModified, o.StorageClass)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "", "Key prefix filter")
	cmd.Flags().Int32Var(&maxKeys, "max-keys", 100, "Maximum keys to return")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ============================ EC2 ============================

func newAWSEC2Cmd() *cobra.Command {
	ec2Cmd := &cobra.Command{
		Use:   "ec2",
		Short: "EC2 enumeration (instances, security groups, VPCs)",
	}
	ec2Cmd.AddCommand(newEC2InstancesCmd())
	ec2Cmd.AddCommand(newEC2SecurityGroupsCmd())
	ec2Cmd.AddCommand(newEC2VpcsCmd())
	return ec2Cmd
}

func newEC2InstancesCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "instances",
		Short: "List EC2 instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			instances, err := factory.ListEC2Instances(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(instances)
				return nil
			}
			if len(instances) == 0 {
				fmt.Println("No EC2 instances found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "INSTANCE ID\tSTATE\tTYPE\tPRIVATE IP\tPUBLIC IP\tNAME")
			for _, i := range instances {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					i.InstanceID, i.State, i.InstanceType, i.PrivateIP, i.PublicIP, i.Name)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newEC2SecurityGroupsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "security-groups",
		Aliases: []string{"sgs"},
		Short: "List EC2 security groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			groups, err := factory.ListSecurityGroups(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(groups)
				return nil
			}
			if len(groups) == 0 {
				fmt.Println("No security groups found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "GROUP ID\tNAME\tVPC\tINGRESS\tEGRESS\tDESCRIPTION")
			for _, g := range groups {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
					g.GroupID, g.GroupName, g.VpcID, g.IngressCount, g.EgressCount,
					truncate(g.Description, 40))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newEC2VpcsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "vpcs",
		Short: "List VPCs",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			vpcs, err := factory.ListVPCs(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(vpcs)
				return nil
			}
			if len(vpcs) == 0 {
				fmt.Println("No VPCs found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "VPC ID\tCIDR\tSTATE\tDEFAULT\tNAME")
			for _, v := range vpcs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n",
					v.VpcID, v.CidrBlock, v.State, v.IsDefault, v.Name)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ============================ Lambda ============================

func newAWSLambdaCmd() *cobra.Command {
	lambdaCmd := &cobra.Command{
		Use:   "lambda",
		Short: "Lambda enumeration",
	}
	lambdaCmd.AddCommand(newLambdaFunctionsCmd())
	return lambdaCmd
}

func newLambdaFunctionsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "functions",
		Short: "List Lambda functions",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			fns, err := factory.ListLambdaFunctions(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(fns)
				return nil
			}
			if len(fns) == 0 {
				fmt.Println("No Lambda functions found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "FUNCTION\tRUNTIME\tMEMORY\tTIMEOUT\tROLE")
			for _, fn := range fns {
				fmt.Fprintf(w, "%s\t%s\t%dMB\t%ds\t%s\n",
					fn.FunctionName, fn.Runtime, fn.MemorySize, fn.Timeout,
					truncate(fn.Role, 50))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ============================ Secrets Manager ============================

func newAWSSecretsCmd() *cobra.Command {
	secretsCmd := &cobra.Command{
		Use:   "secrets",
		Short: "Secrets Manager enumeration",
	}
	secretsCmd.AddCommand(newSecretsListCmd())
	secretsCmd.AddCommand(newSecretsGetCmd())
	return secretsCmd
}

func newSecretsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets (metadata only — does not retrieve values)",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			secrets, err := factory.ListSecrets(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(secrets)
				return nil
			}
			if len(secrets) == 0 {
				fmt.Println("No secrets found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tLAST ACCESSED\tLAST CHANGED\tDESCRIPTION")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					s.Name, s.LastAccessed, s.LastChanged, truncate(s.Description, 40))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newSecretsGetCmd() *cobra.Command {
	var retrieveValue bool
	cmd := &cobra.Command{
		Use:   "get <secret-name-or-arn>",
		Short: "Get a secret's value (requires --retrieve-value)",
		Long: `Retrieve the plaintext value of a secret from Secrets Manager.

SAFETY RAIL: You must pass --retrieve-value to confirm you intend to
fetch the actual secret material. Without it, only metadata is shown.
This prevents accidental secret exfiltration in logs and recordings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !retrieveValue {
				fmt.Fprintln(os.Stderr, "Safety rail: pass --retrieve-value to fetch the actual secret.")
				fmt.Fprintln(os.Stderr, "Without it, this command only confirms the secret exists.")

				factory, creds, cleanup, err := awsClientSetup()
				if err != nil {
					return err
				}
				defer cleanup()

				secrets, err := factory.ListSecrets(context.Background(), creds)
				if err != nil {
					return err
				}
				for _, s := range secrets {
					if s.Name == args[0] || s.ARN == args[0] {
						fmt.Printf("Secret exists: %s\n", s.Name)
						fmt.Printf("  ARN:           %s\n", s.ARN)
						fmt.Printf("  Last accessed: %s\n", s.LastAccessed)
						fmt.Printf("  Last changed:  %s\n", s.LastChanged)
						return nil
					}
				}
				fmt.Printf("Secret not found in list: %s\n", args[0])
				return nil
			}

			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			val, err := factory.GetSecretValue(context.Background(), creds, args[0])
			if err != nil {
				return err
			}
			fmt.Println(val)
			return nil
		},
	}
	cmd.Flags().BoolVar(&retrieveValue, "retrieve-value", false,
		"Actually retrieve the secret value (safety confirmation)")
	return cmd
}

// ============================ SSM ============================

func newAWSSSMCmd() *cobra.Command {
	ssmCmd := &cobra.Command{
		Use:   "ssm",
		Short: "SSM Parameter Store enumeration",
	}
	ssmCmd.AddCommand(newSSMParametersCmd())
	ssmCmd.AddCommand(newSSMGetCmd())
	return ssmCmd
}

func newSSMParametersCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "parameters",
		Short: "List SSM parameters",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			params, err := factory.ListSSMParameters(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(params)
				return nil
			}
			if len(params) == 0 {
				fmt.Println("No SSM parameters found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tVERSION\tLAST MODIFIED")
			for _, p := range params {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", p.Name, p.Type, p.Version, p.LastModified)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newSSMGetCmd() *cobra.Command {
	var retrieveValue bool
	cmd := &cobra.Command{
		Use:   "get <parameter-name>",
		Short: "Get an SSM parameter value (requires --retrieve-value for SecureString)",
		Long: `Retrieve the value of an SSM parameter.

SAFETY RAIL: For SecureString parameters, you must pass --retrieve-value
to decrypt the value. Without it, the encrypted value is returned.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			value, paramType, err := factory.GetSSMParameterValue(
				context.Background(), creds, args[0], retrieveValue,
			)
			if err != nil {
				return err
			}

			fmt.Printf("Name: %s\n", args[0])
			fmt.Printf("Type: %s\n", paramType)
			if paramType == "SecureString" && !retrieveValue {
				fmt.Println("Value: [ENCRYPTED — pass --retrieve-value to decrypt]")
			} else {
				fmt.Printf("Value: %s\n", value)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&retrieveValue, "retrieve-value", false,
		"Decrypt SecureString parameters (safety confirmation)")
	return cmd
}

// ============================ CloudTrail ============================

func newAWSCloudTrailCmd() *cobra.Command {
	ctCmd := &cobra.Command{
		Use:   "cloudtrail",
		Aliases: []string{"ct"},
		Short: "CloudTrail event lookup",
	}
	ctCmd.AddCommand(newCloudTrailEventsCmd())
	return ctCmd
}

func newCloudTrailEventsCmd() *cobra.Command {
	var maxResults int32
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Look up recent CloudTrail events",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			events, err := factory.LookupCloudTrailEvents(context.Background(), creds, maxResults)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(events)
				return nil
			}
			if len(events) == 0 {
				fmt.Println("No CloudTrail events found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TIME\tEVENT\tSOURCE\tUSER\tSOURCE IP")
			for _, e := range events {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					e.EventTime, e.EventName, e.EventSource, e.Username, e.SourceIP)
			}
			return w.Flush()
		},
	}
	cmd.Flags().Int32Var(&maxResults, "max-results", 50, "Maximum events to return")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ============================ KMS ============================

func newAWSKMSCmd() *cobra.Command {
	kmsCmd := &cobra.Command{
		Use:   "kms",
		Short: "KMS key enumeration",
	}
	kmsCmd.AddCommand(newKMSKeysCmd())
	return kmsCmd
}

func newKMSKeysCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List KMS keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			keys, err := factory.ListKMSKeys(context.Background(), creds)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(keys)
				return nil
			}
			if len(keys) == 0 {
				fmt.Println("No KMS keys found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KEY ID\tALIASES\tARN")
			for _, k := range keys {
				aliases := "(none)"
				if len(k.Aliases) > 0 {
					aliases = k.Aliases[0]
					if len(k.Aliases) > 1 {
						aliases += fmt.Sprintf(" (+%d)", len(k.Aliases)-1)
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", truncate(k.KeyID, 20), aliases, k.KeyARN)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ============================ CloudWatch Logs ============================

func newAWSLogsCmd() *cobra.Command {
	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "CloudWatch Logs enumeration",
	}
	logsCmd.AddCommand(newLogsGroupsCmd())
	return logsCmd
}

func newLogsGroupsCmd() *cobra.Command {
	var prefix string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List CloudWatch log groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			factory, creds, cleanup, err := awsClientSetup()
			if err != nil {
				return err
			}
			defer cleanup()

			groups, err := factory.ListLogGroups(context.Background(), creds, prefix)
			if err != nil {
				return err
			}
			if asJSON {
				printJSON(groups)
				return nil
			}
			if len(groups) == 0 {
				fmt.Println("No log groups found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "LOG GROUP\tSTORED BYTES\tRETENTION")
			for _, g := range groups {
				ret := "Never expire"
				if g.RetentionDays > 0 {
					ret = fmt.Sprintf("%d days", g.RetentionDays)
				}
				fmt.Fprintf(w, "%s\t%d\t%s\n", g.Name, g.StoredBytes, ret)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "", "Log group name prefix filter")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// ---- small helpers ----

func printList(label string, items []string) {
	if len(items) == 0 {
		fmt.Printf("%s: (none)\n", label)
		return
	}
	fmt.Printf("%s:\n", label)
	for _, item := range items {
		fmt.Printf("    - %s\n", item)
	}
}
