// Package aws — high-level AWS service operations used by CLI commands.
// All read-only operations leverage the ResponseCache for deduplication.
package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ---- IAM operations ----

type IAMUserSummary struct {
	UserName   string `json:"user_name"`
	UserID     string `json:"user_id"`
	ARN        string `json:"arn"`
	CreateDate string `json:"create_date"`
}

type IAMRoleSummary struct {
	RoleName   string `json:"role_name"`
	RoleID     string `json:"role_id"`
	ARN        string `json:"arn"`
	CreateDate string `json:"create_date"`
}

type IAMPolicySummary struct {
	PolicyName string `json:"policy_name"`
	PolicyID   string `json:"policy_id"`
	ARN        string `json:"arn"`
	IsAttached bool   `json:"is_attached"`
}

type IAMUserDetail struct {
	UserName       string   `json:"user_name"`
	ARN            string   `json:"arn"`
	UserID         string   `json:"user_id"`
	CreateDate     string   `json:"create_date"`
	Groups         []string `json:"groups"`
	AttachedPolicies []string `json:"attached_policies"`
	InlinePolicies   []string `json:"inline_policies"`
	AccessKeys       []string `json:"access_keys"`
	MFADevices       []string `json:"mfa_devices"`
}

type IAMRoleDetail struct {
	RoleName               string   `json:"role_name"`
	ARN                    string   `json:"arn"`
	RoleID                 string   `json:"role_id"`
	CreateDate             string   `json:"create_date"`
	AssumeRolePolicyDoc    string   `json:"assume_role_policy_document"`
	AttachedPolicies       []string `json:"attached_policies"`
	InlinePolicies         []string `json:"inline_policies"`
	InstanceProfileARNs    []string `json:"instance_profile_arns"`
}

func (f *ClientFactory) ListIAMUsers(ctx context.Context, creds SessionCredentials) ([]IAMUserSummary, error) {
	cacheKey := "iam:users:" + creds.AccessKeyID
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]IAMUserSummary), nil
	}

	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "ListUsers", nil, nil)

	client := f.IAMClient(creds)
	var users []IAMUserSummary
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListUsers: %w", err)
		}
		for _, u := range page.Users {
			users = append(users, IAMUserSummary{
				UserName:   aws.ToString(u.UserName),
				UserID:     aws.ToString(u.UserId),
				ARN:        aws.ToString(u.Arn),
				CreateDate: u.CreateDate.Format("2006-01-02"),
			})
		}
		f.rateLimiter.Wait("iam")
	}
	f.cache.Put(cacheKey, users)
	return users, nil
}

func (f *ClientFactory) ListIAMRoles(ctx context.Context, creds SessionCredentials) ([]IAMRoleSummary, error) {
	cacheKey := "iam:roles:" + creds.AccessKeyID
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]IAMRoleSummary), nil
	}

	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "ListRoles", nil, nil)

	client := f.IAMClient(creds)
	var roles []IAMRoleSummary
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListRoles: %w", err)
		}
		for _, r := range page.Roles {
			roles = append(roles, IAMRoleSummary{
				RoleName:   aws.ToString(r.RoleName),
				RoleID:     aws.ToString(r.RoleId),
				ARN:        aws.ToString(r.Arn),
				CreateDate: r.CreateDate.Format("2006-01-02"),
			})
		}
		f.rateLimiter.Wait("iam")
	}
	f.cache.Put(cacheKey, roles)
	return roles, nil
}

func (f *ClientFactory) ListIAMPolicies(ctx context.Context, creds SessionCredentials, onlyAttached bool) ([]IAMPolicySummary, error) {
	cacheKey := fmt.Sprintf("iam:policies:%s:%v", creds.AccessKeyID, onlyAttached)
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]IAMPolicySummary), nil
	}

	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "ListPolicies", nil, nil)

	client := f.IAMClient(creds)
	var policies []IAMPolicySummary
	paginator := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{
		OnlyAttached: onlyAttached,
		Scope:        "Local",
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListPolicies: %w", err)
		}
		for _, p := range page.Policies {
			policies = append(policies, IAMPolicySummary{
				PolicyName: aws.ToString(p.PolicyName),
				PolicyID:   aws.ToString(p.PolicyId),
				ARN:        aws.ToString(p.Arn),
				IsAttached: p.AttachmentCount != nil && *p.AttachmentCount > 0,
			})
		}
		f.rateLimiter.Wait("iam")
	}
	f.cache.Put(cacheKey, policies)
	return policies, nil
}

func (f *ClientFactory) GetIAMUserDetail(ctx context.Context, creds SessionCredentials, userName string) (*IAMUserDetail, error) {
	cacheKey := "iam:user-detail:" + creds.AccessKeyID + ":" + userName
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.(*IAMUserDetail), nil
	}

	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "GetUser", map[string]string{"user": userName}, nil)

	client := f.IAMClient(creds)
	out, err := client.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
	if err != nil {
		return nil, fmt.Errorf("GetUser(%s): %w", userName, err)
	}

	detail := &IAMUserDetail{
		UserName:   aws.ToString(out.User.UserName),
		ARN:        aws.ToString(out.User.Arn),
		UserID:     aws.ToString(out.User.UserId),
		CreateDate: out.User.CreateDate.Format("2006-01-02 15:04:05"),
	}

	// Groups
	f.rateLimiter.Wait("iam")
	grps, err := client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: &userName})
	if err == nil {
		for _, g := range grps.Groups {
			detail.Groups = append(detail.Groups, aws.ToString(g.GroupName))
		}
	}

	// Attached policies
	f.rateLimiter.Wait("iam")
	ap, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &userName})
	if err == nil {
		for _, p := range ap.AttachedPolicies {
			detail.AttachedPolicies = append(detail.AttachedPolicies, aws.ToString(p.PolicyArn))
		}
	}

	// Inline policies
	f.rateLimiter.Wait("iam")
	ip, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &userName})
	if err == nil {
		detail.InlinePolicies = ip.PolicyNames
	}

	// Access keys
	f.rateLimiter.Wait("iam")
	ak, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &userName})
	if err == nil {
		for _, k := range ak.AccessKeyMetadata {
			detail.AccessKeys = append(detail.AccessKeys, aws.ToString(k.AccessKeyId)+" ("+string(k.Status)+")")
		}
	}

	// MFA devices
	f.rateLimiter.Wait("iam")
	mfa, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: &userName})
	if err == nil {
		for _, d := range mfa.MFADevices {
			detail.MFADevices = append(detail.MFADevices, aws.ToString(d.SerialNumber))
		}
	}

	f.cache.Put(cacheKey, detail)
	return detail, nil
}

func (f *ClientFactory) GetIAMRoleDetail(ctx context.Context, creds SessionCredentials, roleName string) (*IAMRoleDetail, error) {
	cacheKey := "iam:role-detail:" + creds.AccessKeyID + ":" + roleName
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.(*IAMRoleDetail), nil
	}

	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "GetRole", map[string]string{"role": roleName}, nil)

	client := f.IAMClient(creds)
	out, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil {
		return nil, fmt.Errorf("GetRole(%s): %w", roleName, err)
	}

	detail := &IAMRoleDetail{
		RoleName:            aws.ToString(out.Role.RoleName),
		ARN:                 aws.ToString(out.Role.Arn),
		RoleID:              aws.ToString(out.Role.RoleId),
		CreateDate:          out.Role.CreateDate.Format("2006-01-02 15:04:05"),
		AssumeRolePolicyDoc: aws.ToString(out.Role.AssumeRolePolicyDocument),
	}

	// Attached policies
	f.rateLimiter.Wait("iam")
	ap, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &roleName})
	if err == nil {
		for _, p := range ap.AttachedPolicies {
			detail.AttachedPolicies = append(detail.AttachedPolicies, aws.ToString(p.PolicyArn))
		}
	}

	// Inline policies
	f.rateLimiter.Wait("iam")
	ip, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &roleName})
	if err == nil {
		detail.InlinePolicies = ip.PolicyNames
	}

	// Instance profiles
	f.rateLimiter.Wait("iam")
	ips, err := client.ListInstanceProfilesForRole(ctx, &iam.ListInstanceProfilesForRoleInput{RoleName: &roleName})
	if err == nil {
		for _, ip := range ips.InstanceProfiles {
			detail.InstanceProfileARNs = append(detail.InstanceProfileARNs, aws.ToString(ip.Arn))
		}
	}

	f.cache.Put(cacheKey, detail)
	return detail, nil
}

// ---- S3 operations ----

type S3BucketSummary struct {
	Name         string `json:"name"`
	CreationDate string `json:"creation_date"`
}

func (f *ClientFactory) ListS3Buckets(ctx context.Context, creds SessionCredentials) ([]S3BucketSummary, error) {
	cacheKey := "s3:buckets:" + creds.AccessKeyID
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]S3BucketSummary), nil
	}

	f.rateLimiter.Wait("s3")
	f.logAPICall("s3", "ListBuckets", nil, nil)

	client := f.S3Client(creds)
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("ListBuckets: %w", err)
	}

	var buckets []S3BucketSummary
	for _, b := range out.Buckets {
		date := ""
		if b.CreationDate != nil {
			date = b.CreationDate.Format("2006-01-02")
		}
		buckets = append(buckets, S3BucketSummary{
			Name:         aws.ToString(b.Name),
			CreationDate: date,
		})
	}
	f.cache.Put(cacheKey, buckets)
	return buckets, nil
}

func (f *ClientFactory) GetBucketPolicy(ctx context.Context, creds SessionCredentials, bucket string) (string, error) {
	cacheKey := "s3:policy:" + creds.AccessKeyID + ":" + bucket
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.(string), nil
	}

	f.rateLimiter.Wait("s3")
	f.logAPICall("s3", "GetBucketPolicy", map[string]string{"bucket": bucket}, nil)

	client := f.S3Client(creds)
	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
	if err != nil {
		return "", fmt.Errorf("GetBucketPolicy(%s): %w", bucket, err)
	}

	policy := aws.ToString(out.Policy)
	f.cache.Put(cacheKey, policy)
	return policy, nil
}

type S3ObjectSummary struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"last_modified"`
	StorageClass string `json:"storage_class"`
}

func (f *ClientFactory) ListS3Objects(ctx context.Context, creds SessionCredentials, bucket, prefix string, maxKeys int32) ([]S3ObjectSummary, error) {
	f.rateLimiter.Wait("s3")
	f.logAPICall("s3", "ListObjectsV2", map[string]string{"bucket": bucket}, nil)

	client := f.S3Client(creds)
	input := &s3.ListObjectsV2Input{
		Bucket:  &bucket,
		MaxKeys: &maxKeys,
	}
	if prefix != "" {
		input.Prefix = &prefix
	}

	out, err := client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("ListObjectsV2(%s): %w", bucket, err)
	}

	var objects []S3ObjectSummary
	for _, o := range out.Contents {
		lm := ""
		if o.LastModified != nil {
			lm = o.LastModified.Format("2006-01-02 15:04")
		}
		objects = append(objects, S3ObjectSummary{
			Key:          aws.ToString(o.Key),
			Size:         aws.ToInt64(o.Size),
			LastModified: lm,
			StorageClass: string(o.StorageClass),
		})
	}
	return objects, nil
}

// ---- EC2 operations ----

type EC2InstanceSummary struct {
	InstanceID   string `json:"instance_id"`
	State        string `json:"state"`
	InstanceType string `json:"instance_type"`
	PrivateIP    string `json:"private_ip"`
	PublicIP     string `json:"public_ip"`
	Name         string `json:"name"`
	LaunchTime   string `json:"launch_time"`
}

func (f *ClientFactory) ListEC2Instances(ctx context.Context, creds SessionCredentials) ([]EC2InstanceSummary, error) {
	cacheKey := "ec2:instances:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]EC2InstanceSummary), nil
	}

	f.rateLimiter.Wait("ec2")
	f.logAPICall("ec2", "DescribeInstances", nil, nil)

	client := f.EC2Client(creds)
	var instances []EC2InstanceSummary
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeInstances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				name := ""
				for _, t := range i.Tags {
					if aws.ToString(t.Key) == "Name" {
						name = aws.ToString(t.Value)
					}
				}
				state := ""
				if i.State != nil {
					state = string(i.State.Name)
				}
				instances = append(instances, EC2InstanceSummary{
					InstanceID:   aws.ToString(i.InstanceId),
					State:        state,
					InstanceType: string(i.InstanceType),
					PrivateIP:    aws.ToString(i.PrivateIpAddress),
					PublicIP:     aws.ToString(i.PublicIpAddress),
					Name:         name,
					LaunchTime:   safeTimePtr(i.LaunchTime),
				})
			}
		}
		f.rateLimiter.Wait("ec2")
	}
	f.cache.Put(cacheKey, instances)
	return instances, nil
}

type SecurityGroupSummary struct {
	GroupID     string `json:"group_id"`
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
	VpcID       string `json:"vpc_id"`
	IngressCount int   `json:"ingress_count"`
	EgressCount  int   `json:"egress_count"`
}

func (f *ClientFactory) ListSecurityGroups(ctx context.Context, creds SessionCredentials) ([]SecurityGroupSummary, error) {
	cacheKey := "ec2:sgs:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]SecurityGroupSummary), nil
	}

	f.rateLimiter.Wait("ec2")
	f.logAPICall("ec2", "DescribeSecurityGroups", nil, nil)

	client := f.EC2Client(creds)
	var groups []SecurityGroupSummary
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeSecurityGroups: %w", err)
		}
		for _, sg := range page.SecurityGroups {
			groups = append(groups, SecurityGroupSummary{
				GroupID:      aws.ToString(sg.GroupId),
				GroupName:    aws.ToString(sg.GroupName),
				Description:  aws.ToString(sg.Description),
				VpcID:        aws.ToString(sg.VpcId),
				IngressCount: len(sg.IpPermissions),
				EgressCount:  len(sg.IpPermissionsEgress),
			})
		}
		f.rateLimiter.Wait("ec2")
	}
	f.cache.Put(cacheKey, groups)
	return groups, nil
}

type VPCSummary struct {
	VpcID     string `json:"vpc_id"`
	CidrBlock string `json:"cidr_block"`
	State     string `json:"state"`
	IsDefault bool   `json:"is_default"`
	Name      string `json:"name"`
}

func (f *ClientFactory) ListVPCs(ctx context.Context, creds SessionCredentials) ([]VPCSummary, error) {
	cacheKey := "ec2:vpcs:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]VPCSummary), nil
	}

	f.rateLimiter.Wait("ec2")
	f.logAPICall("ec2", "DescribeVpcs", nil, nil)

	client := f.EC2Client(creds)
	out, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeVpcs: %w", err)
	}

	var vpcs []VPCSummary
	for _, v := range out.Vpcs {
		name := ""
		for _, t := range v.Tags {
			if aws.ToString(t.Key) == "Name" {
				name = aws.ToString(t.Value)
			}
		}
		vpcs = append(vpcs, VPCSummary{
			VpcID:     aws.ToString(v.VpcId),
			CidrBlock: aws.ToString(v.CidrBlock),
			State:     string(v.State),
			IsDefault: aws.ToBool(v.IsDefault),
			Name:      name,
		})
	}
	f.cache.Put(cacheKey, vpcs)
	return vpcs, nil
}

// ---- Lambda operations ----

type LambdaSummary struct {
	FunctionName string `json:"function_name"`
	Runtime      string `json:"runtime"`
	Handler      string `json:"handler"`
	MemorySize   int32  `json:"memory_size"`
	Timeout      int32  `json:"timeout"`
	LastModified string `json:"last_modified"`
	Role         string `json:"role"`
}

func (f *ClientFactory) ListLambdaFunctions(ctx context.Context, creds SessionCredentials) ([]LambdaSummary, error) {
	cacheKey := "lambda:functions:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]LambdaSummary), nil
	}

	f.rateLimiter.Wait("lambda")
	f.logAPICall("lambda", "ListFunctions", nil, nil)

	client := f.LambdaClient(creds)
	var fns []LambdaSummary
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListFunctions: %w", err)
		}
		for _, fn := range page.Functions {
			var mem int32
			if fn.MemorySize != nil {
				mem = *fn.MemorySize
			}
			var timeout int32
			if fn.Timeout != nil {
				timeout = *fn.Timeout
			}
			fns = append(fns, LambdaSummary{
				FunctionName: aws.ToString(fn.FunctionName),
				Runtime:      string(fn.Runtime),
				Handler:      aws.ToString(fn.Handler),
				MemorySize:   mem,
				Timeout:      timeout,
				LastModified: aws.ToString(fn.LastModified),
				Role:         aws.ToString(fn.Role),
			})
		}
		f.rateLimiter.Wait("lambda")
	}
	f.cache.Put(cacheKey, fns)
	return fns, nil
}

// ---- Secrets Manager operations ----

type SecretSummary struct {
	Name         string `json:"name"`
	ARN          string `json:"arn"`
	Description  string `json:"description"`
	LastAccessed string `json:"last_accessed"`
	LastChanged  string `json:"last_changed"`
}

func (f *ClientFactory) ListSecrets(ctx context.Context, creds SessionCredentials) ([]SecretSummary, error) {
	cacheKey := "secrets:list:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]SecretSummary), nil
	}

	f.rateLimiter.Wait("secretsmanager")
	f.logAPICall("secretsmanager", "ListSecrets", nil, nil)

	client := f.SecretsManagerClient(creds)
	var secrets []SecretSummary
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListSecrets: %w", err)
		}
		for _, s := range page.SecretList {
			la, lc := "", ""
			if s.LastAccessedDate != nil {
				la = s.LastAccessedDate.Format("2006-01-02")
			}
			if s.LastChangedDate != nil {
				lc = s.LastChangedDate.Format("2006-01-02")
			}
			secrets = append(secrets, SecretSummary{
				Name:         aws.ToString(s.Name),
				ARN:          aws.ToString(s.ARN),
				Description:  aws.ToString(s.Description),
				LastAccessed: la,
				LastChanged:  lc,
			})
		}
		f.rateLimiter.Wait("secretsmanager")
	}
	f.cache.Put(cacheKey, secrets)
	return secrets, nil
}

// GetSecretValue retrieves the actual secret value. Requires --retrieve-value flag.
func (f *ClientFactory) GetSecretValue(ctx context.Context, creds SessionCredentials, secretID string) (string, error) {
	f.rateLimiter.Wait("secretsmanager")
	f.logAPICall("secretsmanager", "GetSecretValue", map[string]string{"secret": secretID}, nil)

	client := f.SecretsManagerClient(creds)
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &secretID})
	if err != nil {
		return "", fmt.Errorf("GetSecretValue(%s): %w", secretID, err)
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	return fmt.Sprintf("[binary: %d bytes]", len(out.SecretBinary)), nil
}

// ---- SSM operations ----

type SSMParameterSummary struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Version      int64  `json:"version"`
	LastModified string `json:"last_modified"`
}

func (f *ClientFactory) ListSSMParameters(ctx context.Context, creds SessionCredentials) ([]SSMParameterSummary, error) {
	cacheKey := "ssm:parameters:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]SSMParameterSummary), nil
	}

	f.rateLimiter.Wait("ssm")
	f.logAPICall("ssm", "DescribeParameters", nil, nil)

	client := f.SSMClient(creds)
	var params []SSMParameterSummary
	paginator := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeParameters: %w", err)
		}
		for _, p := range page.Parameters {
			lm := ""
			if p.LastModifiedDate != nil {
				lm = p.LastModifiedDate.Format("2006-01-02 15:04")
			}
			params = append(params, SSMParameterSummary{
				Name:         aws.ToString(p.Name),
				Type:         string(p.Type),
				Version:      p.Version,
				LastModified: lm,
			})
		}
		f.rateLimiter.Wait("ssm")
	}
	f.cache.Put(cacheKey, params)
	return params, nil
}

// GetSSMParameterValue retrieves a parameter value. Requires --retrieve-value for SecureString.
func (f *ClientFactory) GetSSMParameterValue(ctx context.Context, creds SessionCredentials, name string, withDecryption bool) (string, string, error) {
	f.rateLimiter.Wait("ssm")
	f.logAPICall("ssm", "GetParameter", map[string]string{"name": name}, nil)

	client := f.SSMClient(creds)
	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           &name,
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return "", "", fmt.Errorf("GetParameter(%s): %w", name, err)
	}
	return aws.ToString(out.Parameter.Value), string(out.Parameter.Type), nil
}

// ---- CloudTrail operations ----

type CloudTrailEventSummary struct {
	EventID    string `json:"event_id"`
	EventName  string `json:"event_name"`
	EventTime  string `json:"event_time"`
	Username   string `json:"username"`
	SourceIP   string `json:"source_ip"`
	EventSource string `json:"event_source"`
}

func (f *ClientFactory) LookupCloudTrailEvents(ctx context.Context, creds SessionCredentials, maxResults int32) ([]CloudTrailEventSummary, error) {
	f.rateLimiter.Wait("cloudtrail")
	f.logAPICall("cloudtrail", "LookupEvents", nil, nil)

	client := f.CloudTrailClient(creds)
	out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
		MaxResults: &maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("LookupEvents: %w", err)
	}

	var events []CloudTrailEventSummary
	for _, e := range out.Events {
		et := ""
		if e.EventTime != nil {
			et = e.EventTime.Format("2006-01-02 15:04:05")
		}
		events = append(events, CloudTrailEventSummary{
			EventID:     aws.ToString(e.EventId),
			EventName:   aws.ToString(e.EventName),
			EventTime:   et,
			Username:    aws.ToString(e.Username),
			SourceIP:    extractSourceIP(e.CloudTrailEvent),
			EventSource: aws.ToString(e.EventSource),
		})
	}
	return events, nil
}

// ---- KMS operations ----

type KMSKeySummary struct {
	KeyID   string `json:"key_id"`
	KeyARN  string `json:"key_arn"`
	Aliases []string `json:"aliases,omitempty"`
}

func (f *ClientFactory) ListKMSKeys(ctx context.Context, creds SessionCredentials) ([]KMSKeySummary, error) {
	cacheKey := "kms:keys:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]KMSKeySummary), nil
	}

	f.rateLimiter.Wait("kms")
	f.logAPICall("kms", "ListKeys", nil, nil)

	client := f.KMSClient(creds)
	out, err := client.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, fmt.Errorf("ListKeys: %w", err)
	}

	var keys []KMSKeySummary
	for _, k := range out.Keys {
		keys = append(keys, KMSKeySummary{
			KeyID:  aws.ToString(k.KeyId),
			KeyARN: aws.ToString(k.KeyArn),
		})
	}

	// Enrich with aliases
	f.rateLimiter.Wait("kms")
	aliases, err := client.ListAliases(ctx, &kms.ListAliasesInput{})
	if err == nil {
		aliasMap := make(map[string][]string)
		for _, a := range aliases.Aliases {
			kid := aws.ToString(a.TargetKeyId)
			if kid != "" {
				aliasMap[kid] = append(aliasMap[kid], aws.ToString(a.AliasName))
			}
		}
		for i := range keys {
			keys[i].Aliases = aliasMap[keys[i].KeyID]
		}
	}

	f.cache.Put(cacheKey, keys)
	return keys, nil
}

// ---- CloudWatch Logs operations ----

type LogGroupSummary struct {
	Name             string `json:"name"`
	ARN              string `json:"arn"`
	StoredBytes      int64  `json:"stored_bytes"`
	RetentionDays    int32  `json:"retention_days"`
	CreationTime     string `json:"creation_time"`
}

func (f *ClientFactory) ListLogGroups(ctx context.Context, creds SessionCredentials, prefix string) ([]LogGroupSummary, error) {
	cacheKey := "logs:groups:" + creds.AccessKeyID + ":" + creds.Region + ":" + prefix
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]LogGroupSummary), nil
	}

	f.rateLimiter.Wait("logs")
	f.logAPICall("logs", "DescribeLogGroups", nil, nil)

	client := f.CloudWatchLogsClient(creds)
	input := &cloudwatchlogs.DescribeLogGroupsInput{}
	if prefix != "" {
		input.LogGroupNamePrefix = &prefix
	}

	var groups []LogGroupSummary
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeLogGroups: %w", err)
		}
		for _, g := range page.LogGroups {
			var retention int32
			if g.RetentionInDays != nil {
				retention = *g.RetentionInDays
			}
			var storedBytes int64
			if g.StoredBytes != nil {
				storedBytes = *g.StoredBytes
			}
			ct := ""
			if g.CreationTime != nil {
				ct = fmt.Sprintf("%d", *g.CreationTime)
			}
			groups = append(groups, LogGroupSummary{
				Name:          aws.ToString(g.LogGroupName),
				ARN:           aws.ToString(g.Arn),
				StoredBytes:   storedBytes,
				RetentionDays: retention,
				CreationTime:  ct,
			})
		}
		f.rateLimiter.Wait("logs")
	}
	f.cache.Put(cacheKey, groups)
	return groups, nil
}

// ---- EC2 region enumeration ----

func (f *ClientFactory) ListRegions(ctx context.Context, creds SessionCredentials) ([]string, error) {
	cacheKey := "ec2:regions:" + creds.AccessKeyID
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]string), nil
	}

	f.rateLimiter.Wait("ec2")
	client := f.EC2Client(creds)
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("opt-in-status"), Values: []string{"opt-in-not-required", "opted-in"}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeRegions: %w", err)
	}

	var regions []string
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	f.cache.Put(cacheKey, regions)
	return regions, nil
}

// ---- STS operations ----

// AssumeRoleResult holds the output of an STS AssumeRole call.
type AssumeRoleResult struct {
	AccessKeyID    string    `json:"access_key_id"`
	SecretAccessKey string   `json:"secret_access_key"`
	SessionToken   string    `json:"session_token"`
	Expiration     time.Time `json:"expiration"`
	AssumedRoleARN string    `json:"assumed_role_arn"`
}

// AssumeRole calls STS AssumeRole and returns the temporary credentials.
func (f *ClientFactory) AssumeRole(ctx context.Context, creds SessionCredentials, roleARN, sessionName, externalID string, durationSecs int32) (*AssumeRoleResult, error) {
	f.rateLimiter.Wait("sts")
	f.logAPICall("sts", "AssumeRole", map[string]string{
		"role_arn":     roleARN,
		"session_name": sessionName,
	}, nil)

	client := f.STSClient(creds)
	input := &sts.AssumeRoleInput{
		RoleArn:         &roleARN,
		RoleSessionName: &sessionName,
	}
	if externalID != "" {
		input.ExternalId = &externalID
	}
	if durationSecs > 0 {
		input.DurationSeconds = &durationSecs
	}

	out, err := client.AssumeRole(ctx, input)
	if err != nil {
		f.logAPICall("sts", "AssumeRole", map[string]string{"role_arn": roleARN}, err)
		return nil, fmt.Errorf("AssumeRole(%s): %w", roleARN, err)
	}

	result := &AssumeRoleResult{
		AccessKeyID:    aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:   aws.ToString(out.Credentials.SessionToken),
		AssumedRoleARN: aws.ToString(out.AssumedRoleUser.Arn),
	}
	if out.Credentials.Expiration != nil {
		result.Expiration = *out.Credentials.Expiration
	}
	return result, nil
}

// ---- helpers ----

func safeTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02 15:04")
}

func extractSourceIP(rawEvent *string) string {
	if rawEvent == nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(*rawEvent), &m); err != nil {
		return ""
	}
	if ip, ok := m["sourceIPAddress"].(string); ok {
		return ip
	}
	return ""
}

// ---- Write operations (no caching) ----

// CreateAccessKeyResult holds the output of iam:CreateAccessKey.
type CreateAccessKeyResult struct {
	AccessKeyID string `json:"access_key_id"`
	Status      string `json:"status"`
	UserName    string `json:"user_name"`
	CreateDate  string `json:"create_date"`
}

// CreateAccessKey creates a new IAM access key for the specified user.
// The SecretAccessKey is intentionally NOT included in the result struct for security.
func (f *ClientFactory) CreateAccessKey(ctx context.Context, creds SessionCredentials, userName string) (*CreateAccessKeyResult, string, error) {
	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "CreateAccessKey", map[string]string{"user": userName}, nil)

	client := f.IAMClient(creds)
	out, err := client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: &userName,
	})
	if err != nil {
		f.logAPICall("iam", "CreateAccessKey", map[string]string{"user": userName}, err)
		return nil, "", fmt.Errorf("CreateAccessKey(%s): %w", userName, err)
	}

	result := &CreateAccessKeyResult{
		AccessKeyID: aws.ToString(out.AccessKey.AccessKeyId),
		Status:      string(out.AccessKey.Status),
		UserName:    aws.ToString(out.AccessKey.UserName),
		CreateDate:  out.AccessKey.CreateDate.Format("2006-01-02 15:04:05"),
	}
	secretKey := aws.ToString(out.AccessKey.SecretAccessKey)

	return result, secretKey, nil
}

// StopTrail disables logging on a CloudTrail trail.
func (f *ClientFactory) StopTrail(ctx context.Context, creds SessionCredentials, trailName string) error {
	f.rateLimiter.Wait("cloudtrail")
	f.logAPICall("cloudtrail", "StopLogging", map[string]string{"trail": trailName}, nil)

	client := f.CloudTrailClient(creds)
	_, err := client.StopLogging(ctx, &cloudtrail.StopLoggingInput{
		Name: &trailName,
	})
	if err != nil {
		f.logAPICall("cloudtrail", "StopLogging", map[string]string{"trail": trailName}, err)
		return fmt.Errorf("StopLogging(%s): %w", trailName, err)
	}

	return nil
}

// AuthorizeSecurityGroupIngressResult holds the output of ec2:AuthorizeSecurityGroupIngress.
type AuthorizeSecurityGroupIngressResult struct {
	GroupID  string `json:"group_id"`
	Protocol string `json:"protocol"`
	FromPort int32  `json:"from_port"`
	ToPort   int32  `json:"to_port"`
	CidrIP   string `json:"cidr_ip"`
}

// ---- EC2 User Data operations ----

// GetInstanceUserData retrieves the userData attribute of an EC2 instance.
// The returned data is base64-encoded by the AWS API.
func (f *ClientFactory) GetInstanceUserData(ctx context.Context, creds SessionCredentials, instanceID string) (string, error) {
	f.rateLimiter.Wait("ec2")
	f.logAPICall("ec2", "DescribeInstanceAttribute", map[string]string{"instance": instanceID, "attribute": "userData"}, nil)

	client := f.EC2Client(creds)
	out, err := client.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: &instanceID,
		Attribute:  ec2types.InstanceAttributeNameUserData,
	})
	if err != nil {
		return "", fmt.Errorf("DescribeInstanceAttribute(%s, userData): %w", instanceID, err)
	}
	if out.UserData != nil && out.UserData.Value != nil {
		return aws.ToString(out.UserData.Value), nil
	}
	return "", nil
}

// ---- EBS Snapshot operations ----

// EBSSnapshotSummary holds snapshot metadata.
type EBSSnapshotSummary struct {
	SnapshotID  string `json:"snapshot_id"`
	VolumeID    string `json:"volume_id"`
	State       string `json:"state"`
	VolumeSize  int32  `json:"volume_size_gb"`
	Description string `json:"description"`
	Encrypted   bool   `json:"encrypted"`
	OwnerID     string `json:"owner_id"`
	StartTime   string `json:"start_time"`
}

// ListEBSSnapshots lists EBS snapshots owned by the current account.
func (f *ClientFactory) ListEBSSnapshots(ctx context.Context, creds SessionCredentials) ([]EBSSnapshotSummary, error) {
	cacheKey := "ec2:snapshots:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]EBSSnapshotSummary), nil
	}

	f.rateLimiter.Wait("ec2")
	f.logAPICall("ec2", "DescribeSnapshots", nil, nil)

	client := f.EC2Client(creds)
	var snapshots []EBSSnapshotSummary
	paginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeSnapshots: %w", err)
		}
		for _, s := range page.Snapshots {
			snapshots = append(snapshots, EBSSnapshotSummary{
				SnapshotID:  aws.ToString(s.SnapshotId),
				VolumeID:    aws.ToString(s.VolumeId),
				State:       string(s.State),
				VolumeSize:  aws.ToInt32(s.VolumeSize),
				Description: aws.ToString(s.Description),
				Encrypted:   aws.ToBool(s.Encrypted),
				OwnerID:     aws.ToString(s.OwnerId),
				StartTime:   safeTimePtr(s.StartTime),
			})
		}
		f.rateLimiter.Wait("ec2")
	}
	f.cache.Put(cacheKey, snapshots)
	return snapshots, nil
}

// ---- RDS operations ----

// RDSInstanceSummary holds RDS instance metadata.
type RDSInstanceSummary struct {
	DBInstanceID   string `json:"db_instance_id"`
	Engine         string `json:"engine"`
	EngineVersion  string `json:"engine_version"`
	InstanceClass  string `json:"instance_class"`
	Endpoint       string `json:"endpoint"`
	Port           int32  `json:"port"`
	MasterUsername string `json:"master_username"`
	PublicAccess   bool   `json:"publicly_accessible"`
	Encrypted      bool   `json:"encrypted"`
	Status         string `json:"status"`
	MultiAZ        bool   `json:"multi_az"`
}

// ListRDSInstances enumerates RDS database instances.
func (f *ClientFactory) ListRDSInstances(ctx context.Context, creds SessionCredentials) ([]RDSInstanceSummary, error) {
	cacheKey := "rds:instances:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]RDSInstanceSummary), nil
	}

	f.rateLimiter.Wait("rds")
	f.logAPICall("rds", "DescribeDBInstances", nil, nil)

	client := f.RDSClient(creds)
	var instances []RDSInstanceSummary
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeDBInstances: %w", err)
		}
		for _, db := range page.DBInstances {
			endpoint := ""
			var port int32
			if db.Endpoint != nil {
				endpoint = aws.ToString(db.Endpoint.Address)
				if db.Endpoint.Port != nil {
					port = *db.Endpoint.Port
				}
			}
			instances = append(instances, RDSInstanceSummary{
				DBInstanceID:   aws.ToString(db.DBInstanceIdentifier),
				Engine:         aws.ToString(db.Engine),
				EngineVersion:  aws.ToString(db.EngineVersion),
				InstanceClass:  aws.ToString(db.DBInstanceClass),
				Endpoint:       endpoint,
				Port:           port,
				MasterUsername: aws.ToString(db.MasterUsername),
				PublicAccess:   aws.ToBool(db.PubliclyAccessible),
				Encrypted:      aws.ToBool(db.StorageEncrypted),
				Status:         aws.ToString(db.DBInstanceStatus),
				MultiAZ:        aws.ToBool(db.MultiAZ),
			})
		}
		f.rateLimiter.Wait("rds")
	}
	f.cache.Put(cacheKey, instances)
	return instances, nil
}

// RDSSnapshotSummary holds RDS snapshot metadata.
type RDSSnapshotSummary struct {
	SnapshotID  string `json:"snapshot_id"`
	DBInstance  string `json:"db_instance"`
	Engine      string `json:"engine"`
	Status      string `json:"status"`
	Encrypted   bool   `json:"encrypted"`
	SnapshotType string `json:"snapshot_type"`
	CreateTime  string `json:"create_time"`
}

// ListRDSSnapshots enumerates RDS snapshots.
func (f *ClientFactory) ListRDSSnapshots(ctx context.Context, creds SessionCredentials) ([]RDSSnapshotSummary, error) {
	cacheKey := "rds:snapshots:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]RDSSnapshotSummary), nil
	}

	f.rateLimiter.Wait("rds")
	f.logAPICall("rds", "DescribeDBSnapshots", nil, nil)

	client := f.RDSClient(creds)
	var snapshots []RDSSnapshotSummary
	paginator := rds.NewDescribeDBSnapshotsPaginator(client, &rds.DescribeDBSnapshotsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeDBSnapshots: %w", err)
		}
		for _, s := range page.DBSnapshots {
			ct := ""
			if s.SnapshotCreateTime != nil {
				ct = s.SnapshotCreateTime.Format("2006-01-02 15:04")
			}
			snapshots = append(snapshots, RDSSnapshotSummary{
				SnapshotID:   aws.ToString(s.DBSnapshotIdentifier),
				DBInstance:   aws.ToString(s.DBInstanceIdentifier),
				Engine:       aws.ToString(s.Engine),
				Status:       aws.ToString(s.Status),
				Encrypted:    aws.ToBool(s.Encrypted),
				SnapshotType: aws.ToString(s.SnapshotType),
				CreateTime:   ct,
			})
		}
		f.rateLimiter.Wait("rds")
	}
	f.cache.Put(cacheKey, snapshots)
	return snapshots, nil
}

// ---- DynamoDB operations ----

// DynamoDBTableSummary holds DynamoDB table metadata.
type DynamoDBTableSummary struct {
	TableName   string `json:"table_name"`
	TableARN    string `json:"table_arn"`
	Status      string `json:"status"`
	ItemCount   int64  `json:"item_count"`
	SizeBytes   int64  `json:"size_bytes"`
	TableClass  string `json:"table_class"`
	Encrypted   bool   `json:"encrypted"`
}

// ListDynamoDBTables lists DynamoDB tables with detail.
func (f *ClientFactory) ListDynamoDBTables(ctx context.Context, creds SessionCredentials) ([]DynamoDBTableSummary, error) {
	cacheKey := "dynamodb:tables:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]DynamoDBTableSummary), nil
	}

	f.rateLimiter.Wait("dynamodb")
	f.logAPICall("dynamodb", "ListTables", nil, nil)

	client := f.DynamoDBClient(creds)
	var tableNames []string
	paginator := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListTables: %w", err)
		}
		tableNames = append(tableNames, page.TableNames...)
		f.rateLimiter.Wait("dynamodb")
	}

	var tables []DynamoDBTableSummary
	for _, name := range tableNames {
		f.rateLimiter.Wait("dynamodb")
		desc, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &name})
		if err != nil {
			continue
		}
		t := desc.Table
		encrypted := t.SSEDescription != nil && t.SSEDescription.Status == "ENABLED"
		tableClass := "STANDARD"
		if t.TableClassSummary != nil {
			tableClass = string(t.TableClassSummary.TableClass)
		}
		tables = append(tables, DynamoDBTableSummary{
			TableName:  aws.ToString(t.TableName),
			TableARN:   aws.ToString(t.TableArn),
			Status:     string(t.TableStatus),
			ItemCount:  aws.ToInt64(t.ItemCount),
			SizeBytes:  aws.ToInt64(t.TableSizeBytes),
			TableClass: tableClass,
			Encrypted:  encrypted,
		})
	}
	f.cache.Put(cacheKey, tables)
	return tables, nil
}

// ---- ECS operations ----

// ECSClusterSummary holds ECS cluster metadata.
type ECSClusterSummary struct {
	ClusterARN            string `json:"cluster_arn"`
	ClusterName           string `json:"cluster_name"`
	Status                string `json:"status"`
	RunningTaskCount      int32  `json:"running_tasks"`
	ActiveServicesCount   int32  `json:"active_services"`
	RegisteredContainers  int32  `json:"registered_containers"`
}

// ListECSClusters enumerates ECS clusters.
func (f *ClientFactory) ListECSClusters(ctx context.Context, creds SessionCredentials) ([]ECSClusterSummary, error) {
	cacheKey := "ecs:clusters:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]ECSClusterSummary), nil
	}

	f.rateLimiter.Wait("ecs")
	f.logAPICall("ecs", "ListClusters", nil, nil)

	client := f.ECSClient(creds)
	var clusterARNs []string
	paginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListClusters: %w", err)
		}
		clusterARNs = append(clusterARNs, page.ClusterArns...)
		f.rateLimiter.Wait("ecs")
	}

	if len(clusterARNs) == 0 {
		f.cache.Put(cacheKey, []ECSClusterSummary{})
		return nil, nil
	}

	f.rateLimiter.Wait("ecs")
	f.logAPICall("ecs", "DescribeClusters", nil, nil)
	desc, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: clusterARNs,
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeClusters: %w", err)
	}

	var clusters []ECSClusterSummary
	for _, c := range desc.Clusters {
		clusters = append(clusters, ECSClusterSummary{
			ClusterARN:           aws.ToString(c.ClusterArn),
			ClusterName:          aws.ToString(c.ClusterName),
			Status:               aws.ToString(c.Status),
			RunningTaskCount:     c.RunningTasksCount,
			ActiveServicesCount:  c.ActiveServicesCount,
			RegisteredContainers: c.RegisteredContainerInstancesCount,
		})
	}
	f.cache.Put(cacheKey, clusters)
	return clusters, nil
}

// ECSTaskSummary holds ECS task metadata.
type ECSTaskSummary struct {
	TaskARN          string `json:"task_arn"`
	TaskDefinitionARN string `json:"task_definition_arn"`
	ClusterARN       string `json:"cluster_arn"`
	LastStatus       string `json:"last_status"`
	LaunchType       string `json:"launch_type"`
	CPU              string `json:"cpu"`
	Memory           string `json:"memory"`
}

// ListECSTasks lists running tasks in a cluster.
func (f *ClientFactory) ListECSTasks(ctx context.Context, creds SessionCredentials, clusterARN string) ([]ECSTaskSummary, error) {
	f.rateLimiter.Wait("ecs")
	f.logAPICall("ecs", "ListTasks", map[string]string{"cluster": clusterARN}, nil)

	client := f.ECSClient(creds)
	var taskARNs []string
	paginator := ecs.NewListTasksPaginator(client, &ecs.ListTasksInput{
		Cluster:       &clusterARN,
		DesiredStatus: ecstypes.DesiredStatusRunning,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListTasks: %w", err)
		}
		taskARNs = append(taskARNs, page.TaskArns...)
		f.rateLimiter.Wait("ecs")
	}

	if len(taskARNs) == 0 {
		return nil, nil
	}

	f.rateLimiter.Wait("ecs")
	desc, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: &clusterARN,
		Tasks:   taskARNs,
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeTasks: %w", err)
	}

	var tasks []ECSTaskSummary
	for _, t := range desc.Tasks {
		tasks = append(tasks, ECSTaskSummary{
			TaskARN:           aws.ToString(t.TaskArn),
			TaskDefinitionARN: aws.ToString(t.TaskDefinitionArn),
			ClusterARN:        aws.ToString(t.ClusterArn),
			LastStatus:        aws.ToString(t.LastStatus),
			LaunchType:        string(t.LaunchType),
			CPU:               aws.ToString(t.Cpu),
			Memory:            aws.ToString(t.Memory),
		})
	}
	return tasks, nil
}

// ---- SNS operations ----

// SNSTopicSummary holds SNS topic metadata.
type SNSTopicSummary struct {
	TopicARN      string `json:"topic_arn"`
	DisplayName   string `json:"display_name"`
	Subscriptions string `json:"subscriptions_confirmed"`
	Policy        string `json:"policy,omitempty"`
}

// ListSNSTopics lists SNS topics with attributes.
func (f *ClientFactory) ListSNSTopics(ctx context.Context, creds SessionCredentials) ([]SNSTopicSummary, error) {
	cacheKey := "sns:topics:" + creds.AccessKeyID + ":" + creds.Region
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.([]SNSTopicSummary), nil
	}

	f.rateLimiter.Wait("sns")
	f.logAPICall("sns", "ListTopics", nil, nil)

	client := f.SNSClient(creds)
	var topicARNs []string
	paginator := sns.NewListTopicsPaginator(client, &sns.ListTopicsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListTopics: %w", err)
		}
		for _, t := range page.Topics {
			topicARNs = append(topicARNs, aws.ToString(t.TopicArn))
		}
		f.rateLimiter.Wait("sns")
	}

	var topics []SNSTopicSummary
	for _, arn := range topicARNs {
		f.rateLimiter.Wait("sns")
		attrs, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: &arn})
		if err != nil {
			topics = append(topics, SNSTopicSummary{TopicARN: arn})
			continue
		}
		topics = append(topics, SNSTopicSummary{
			TopicARN:      arn,
			DisplayName:   attrs.Attributes["DisplayName"],
			Subscriptions: attrs.Attributes["SubscriptionsConfirmed"],
			Policy:        attrs.Attributes["Policy"],
		})
	}
	f.cache.Put(cacheKey, topics)
	return topics, nil
}

// ---- IAM write operations ----

// UpdateAssumeRolePolicy updates the trust policy on an IAM role.
func (f *ClientFactory) UpdateAssumeRolePolicy(ctx context.Context, creds SessionCredentials, roleName, policyDocument string) error {
	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "UpdateAssumeRolePolicy", map[string]string{"role": roleName}, nil)

	client := f.IAMClient(creds)
	_, err := client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       &roleName,
		PolicyDocument: &policyDocument,
	})
	if err != nil {
		f.logAPICall("iam", "UpdateAssumeRolePolicy", map[string]string{"role": roleName}, err)
		return fmt.Errorf("UpdateAssumeRolePolicy(%s): %w", roleName, err)
	}
	// Invalidate role cache
	f.cache.Clear("iam:role-detail:")
	return nil
}

// GetIAMPolicyVersion retrieves a specific version of an IAM policy document.
func (f *ClientFactory) GetIAMPolicyVersion(ctx context.Context, creds SessionCredentials, policyARN, versionID string) (string, error) {
	cacheKey := "iam:policy-version:" + creds.AccessKeyID + ":" + policyARN + ":" + versionID
	if cached, ok := f.cache.Get(cacheKey); ok {
		return cached.(string), nil
	}

	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "GetPolicyVersion", map[string]string{"policy": policyARN, "version": versionID}, nil)

	client := f.IAMClient(creds)
	out, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyARN,
		VersionId: &versionID,
	})
	if err != nil {
		return "", fmt.Errorf("GetPolicyVersion(%s, %s): %w", policyARN, versionID, err)
	}
	doc := aws.ToString(out.PolicyVersion.Document)
	f.cache.Put(cacheKey, doc)
	return doc, nil
}

// GetIAMPolicyDefaultVersion retrieves the default version of an IAM policy.
func (f *ClientFactory) GetIAMPolicyDefaultVersion(ctx context.Context, creds SessionCredentials, policyARN string) (string, string, error) {
	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "GetPolicy", map[string]string{"policy": policyARN}, nil)

	client := f.IAMClient(creds)
	out, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &policyARN,
	})
	if err != nil {
		return "", "", fmt.Errorf("GetPolicy(%s): %w", policyARN, err)
	}
	return aws.ToString(out.Policy.DefaultVersionId), aws.ToString(out.Policy.Arn), nil
}

// GetIAMUserInlinePolicy retrieves an inline policy document for a user.
func (f *ClientFactory) GetIAMUserInlinePolicy(ctx context.Context, creds SessionCredentials, userName, policyName string) (string, error) {
	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "GetUserPolicy", map[string]string{"user": userName, "policy": policyName}, nil)

	client := f.IAMClient(creds)
	out, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
		UserName:   &userName,
		PolicyName: &policyName,
	})
	if err != nil {
		return "", fmt.Errorf("GetUserPolicy(%s, %s): %w", userName, policyName, err)
	}
	return aws.ToString(out.PolicyDocument), nil
}

// GetIAMRoleInlinePolicy retrieves an inline policy document for a role.
func (f *ClientFactory) GetIAMRoleInlinePolicy(ctx context.Context, creds SessionCredentials, roleName, policyName string) (string, error) {
	f.rateLimiter.Wait("iam")
	f.logAPICall("iam", "GetRolePolicy", map[string]string{"role": roleName, "policy": policyName}, nil)

	client := f.IAMClient(creds)
	out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
		RoleName:   &roleName,
		PolicyName: &policyName,
	})
	if err != nil {
		return "", fmt.Errorf("GetRolePolicy(%s, %s): %w", roleName, policyName, err)
	}
	return aws.ToString(out.PolicyDocument), nil
}

// GetLambdaFunctionEnvVars retrieves environment variables for a Lambda function.
func (f *ClientFactory) GetLambdaFunctionEnvVars(ctx context.Context, creds SessionCredentials, functionName string) (map[string]string, error) {
	f.rateLimiter.Wait("lambda")
	f.logAPICall("lambda", "GetFunctionConfiguration", map[string]string{"function": functionName}, nil)

	client := f.LambdaClient(creds)
	out, err := client.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{
		FunctionName: &functionName,
	})
	if err != nil {
		return nil, fmt.Errorf("GetFunctionConfiguration(%s): %w", functionName, err)
	}
	if out.Environment != nil && out.Environment.Variables != nil {
		return out.Environment.Variables, nil
	}
	return nil, nil
}

// GetS3BucketEncryption checks a bucket's encryption configuration.
func (f *ClientFactory) GetS3BucketEncryption(ctx context.Context, creds SessionCredentials, bucket string) (string, error) {
	f.rateLimiter.Wait("s3")
	f.logAPICall("s3", "GetBucketEncryption", map[string]string{"bucket": bucket}, nil)

	client := f.S3Client(creds)
	out, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
	if err != nil {
		return "", err
	}
	if out.ServerSideEncryptionConfiguration != nil {
		for _, rule := range out.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault != nil {
				return string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm), nil
			}
		}
	}
	return "none", nil
}

// AuthorizeSecurityGroupIngress adds an ingress rule to a security group.
func (f *ClientFactory) AuthorizeSecurityGroupIngress(ctx context.Context, creds SessionCredentials, groupID, protocol, cidrIP string, fromPort, toPort int32) (*AuthorizeSecurityGroupIngressResult, error) {
	f.rateLimiter.Wait("ec2")
	f.logAPICall("ec2", "AuthorizeSecurityGroupIngress", map[string]string{
		"group_id": groupID,
		"protocol": protocol,
		"cidr_ip":  cidrIP,
	}, nil)

	client := f.EC2Client(creds)
	_, err := client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: &groupID,
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: &protocol,
				FromPort:   &fromPort,
				ToPort:     &toPort,
				IpRanges: []ec2types.IpRange{
					{CidrIp: &cidrIP},
				},
			},
		},
	})
	if err != nil {
		f.logAPICall("ec2", "AuthorizeSecurityGroupIngress", map[string]string{"group_id": groupID}, err)
		return nil, fmt.Errorf("AuthorizeSecurityGroupIngress(%s): %w", groupID, err)
	}

	// Invalidate cached security group data
	f.cache.Clear("ec2:sgs:")

	return &AuthorizeSecurityGroupIngressResult{
		GroupID:  groupID,
		Protocol: protocol,
		FromPort: fromPort,
		ToPort:   toPort,
		CidrIP:   cidrIP,
	}, nil
}
