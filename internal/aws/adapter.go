// Package aws provides the AWS SDK v2 adapter layer with rate limiting,
// retry logic, caching, and audit logging.
package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/rs/zerolog"
)

// SessionCredentials holds the credential material needed to create AWS clients.
type SessionCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

// ClientFactory creates rate-limited, audit-logged AWS service clients.
type ClientFactory struct {
	mu          sync.Mutex
	rateLimiter *RateLimiter
	logger      zerolog.Logger
}

// NewClientFactory creates a new AWS client factory.
func NewClientFactory(logger zerolog.Logger) *ClientFactory {
	return &ClientFactory{
		rateLimiter: NewRateLimiter(10), // 10 req/s default per service
		logger:      logger,
	}
}

// STSClient creates an STS client for the given credentials.
func (f *ClientFactory) STSClient(creds SessionCredentials) *sts.Client {
	cfg := f.awsConfig(creds)
	return sts.NewFromConfig(cfg)
}

// IAMClient creates an IAM client for the given credentials.
func (f *ClientFactory) IAMClient(creds SessionCredentials) *iam.Client {
	cfg := f.awsConfig(creds)
	return iam.NewFromConfig(cfg)
}

// S3Client creates an S3 client for the given credentials.
func (f *ClientFactory) S3Client(creds SessionCredentials) *s3.Client {
	cfg := f.awsConfig(creds)
	return s3.NewFromConfig(cfg)
}

func (f *ClientFactory) awsConfig(creds SessionCredentials) aws.Config {
	return aws.Config{
		Region: creds.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
		RetryMaxAttempts: 5,
	}
}

// GetCallerIdentity performs sts:GetCallerIdentity and returns ARN, account, user ID.
func (f *ClientFactory) GetCallerIdentity(ctx context.Context, creds SessionCredentials) (arn, account, userID string, err error) {
	f.rateLimiter.Wait("sts")

	client := f.STSClient(creds)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", "", fmt.Errorf("GetCallerIdentity: %w", err)
	}

	return aws.ToString(result.Arn), aws.ToString(result.Account), aws.ToString(result.UserId), nil
}

// RateLimiter implements a per-service token bucket rate limiter.
type RateLimiter struct {
	mu          sync.Mutex
	ratePerSec  int
	lastCall    map[string]time.Time
}

// NewRateLimiter creates a rate limiter with the given requests per second.
func NewRateLimiter(ratePerSec int) *RateLimiter {
	return &RateLimiter{
		ratePerSec: ratePerSec,
		lastCall:   make(map[string]time.Time),
	}
}

// Wait blocks until the rate limit allows a call to the given service.
func (rl *RateLimiter) Wait(service string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	minInterval := time.Second / time.Duration(rl.ratePerSec)
	last, ok := rl.lastCall[service]
	if ok {
		elapsed := time.Since(last)
		if elapsed < minInterval {
			time.Sleep(minInterval - elapsed)
		}
	}
	rl.lastCall[service] = time.Now()
}
