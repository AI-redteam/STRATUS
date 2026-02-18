package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	awsops "github.com/stratus-framework/stratus/internal/aws"
)

// RegisterAWSRawCommands adds the `stratus awsraw` escape hatch.
func RegisterAWSRawCommands(root *cobra.Command) {
	var (
		service   string
		action    string
		region    string
		paramsRaw string
		sessionID string
	)

	cmd := &cobra.Command{
		Use:   "awsraw",
		Short: "Execute an arbitrary AWS API call (escape hatch)",
		Long: `Execute any AWS API call by specifying the service, action, and parameters.

This is an escape hatch for operations not covered by the built-in 'stratus aws'
commands. It signs and sends the request using the active session credentials.

Examples:
  stratus awsraw --service sts --action GetCallerIdentity
  stratus awsraw --service iam --action ListGroupsForUser --params '{"UserName":"alice"}'
  stratus awsraw --service s3 --action HeadBucket --params '{"Bucket":"my-bucket"}'
  stratus awsraw --service organizations --action ListAccounts`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if service == "" || action == "" {
				return fmt.Errorf("--service and --action are required")
			}

			engine, err := loadActiveEngine()
			if err != nil {
				return err
			}
			defer engine.Close()

			var creds awsops.SessionCredentials
			if sessionID != "" {
				creds, _, err = awsops.ResolveSessionCredentials(engine, sessionID)
			} else {
				creds, _, err = awsops.ResolveActiveCredentials(engine)
			}
			if err != nil {
				return err
			}

			if region != "" {
				creds.Region = region
			}

			// Parse optional params
			params := make(map[string]any)
			if paramsRaw != "" {
				if err := json.Unmarshal([]byte(paramsRaw), &params); err != nil {
					return fmt.Errorf("invalid --params JSON: %w", err)
				}
			}

			// Rate-limit the call
			factory := awsops.NewClientFactory(engine.Logger)
			factory.WaitForService(service)

			result, statusCode, err := awsops.ExecuteRawRequest(
				context.Background(),
				awsops.RawAPIRequest{
					Service: service,
					Action:  action,
					Region:  creds.Region,
					Params:  params,
					Creds:   creds,
				},
			)
			if err != nil {
				return err
			}

			if statusCode >= 400 {
				return fmt.Errorf("AWS API error (HTTP %d):\n%s", statusCode, result)
			}

			// Pretty print if JSON
			var parsed any
			if json.Unmarshal([]byte(result), &parsed) == nil {
				pretty, _ := json.MarshalIndent(parsed, "", "  ")
				fmt.Println(string(pretty))
			} else {
				fmt.Println(result)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&service, "service", "", "AWS service name (e.g. iam, sts, ec2, s3, lambda)")
	cmd.Flags().StringVar(&action, "action", "", "API action name (e.g. ListUsers, DescribeInstances)")
	cmd.Flags().StringVar(&region, "region", "", "Override region (defaults to session region)")
	cmd.Flags().StringVar(&paramsRaw, "params", "", "JSON object of API parameters")
	cmd.Flags().StringVar(&sessionID, "session", "", "Use a specific session UUID instead of the active session")

	root.AddCommand(cmd)
}
