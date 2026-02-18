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
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/rs/zerolog"
	"github.com/stratus-framework/stratus/internal/audit"
)

// SessionCredentials holds the credential material needed to create AWS clients.
type SessionCredentials struct {
	AccessKeyID    string
	SecretAccessKey string
	SessionToken   string
	Region         string
}

// ClientFactory creates rate-limited, audit-logged AWS service clients.
type ClientFactory struct {
	mu          sync.Mutex
	rateLimiter *RateLimiter
	logger      zerolog.Logger
	cache       *ResponseCache
	auditLogger *audit.Logger
	sessionUUID string
}

// NewClientFactory creates a new AWS client factory.
func NewClientFactory(logger zerolog.Logger) *ClientFactory {
	return &ClientFactory{
		rateLimiter: NewRateLimiter(10),
		logger:      logger,
		cache:       NewResponseCache(5 * time.Minute),
	}
}

// NewClientFactoryWithRate creates a factory with a custom rate limit.
func NewClientFactoryWithRate(logger zerolog.Logger, ratePerSec int, cacheTTL time.Duration) *ClientFactory {
	return &ClientFactory{
		rateLimiter: NewRateLimiter(ratePerSec),
		logger:      logger,
		cache:       NewResponseCache(cacheTTL),
	}
}

// NewClientFactoryWithAudit creates a factory that records every API call to
// the audit database.
func NewClientFactoryWithAudit(logger zerolog.Logger, al *audit.Logger, sessionUUID string) *ClientFactory {
	return &ClientFactory{
		rateLimiter: NewRateLimiter(10),
		logger:      logger,
		cache:       NewResponseCache(5 * time.Minute),
		auditLogger: al,
		sessionUUID: sessionUUID,
	}
}

// SetAudit enables audit logging on an existing factory.
func (f *ClientFactory) SetAudit(al *audit.Logger, sessionUUID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auditLogger = al
	f.sessionUUID = sessionUUID
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

// logAPICall records an API call to both the structured logger and the audit database.
func (f *ClientFactory) logAPICall(service, operation string, params map[string]string, err error) {
	f.logger.Debug().Str("service", service).Str("operation", operation).Msg("aws api call")

	if f.auditLogger != nil {
		detail := map[string]string{
			"service":   service,
			"operation": operation,
		}
		for k, v := range params {
			detail[k] = v
		}
		if err != nil {
			detail["error"] = err.Error()
		}
		f.auditLogger.Log(audit.EventAPICall, "local", f.sessionUUID, "", detail)
	}
}

// Cache returns the response cache for manual invalidation.
func (f *ClientFactory) Cache() *ResponseCache { return f.cache }

// --- Service client factories ---

func (f *ClientFactory) STSClient(creds SessionCredentials) *sts.Client {
	return sts.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) IAMClient(creds SessionCredentials) *iam.Client {
	return iam.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) S3Client(creds SessionCredentials) *s3.Client {
	return s3.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) EC2Client(creds SessionCredentials) *ec2.Client {
	return ec2.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) LambdaClient(creds SessionCredentials) *lambda.Client {
	return lambda.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) CloudTrailClient(creds SessionCredentials) *cloudtrail.Client {
	return cloudtrail.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) KMSClient(creds SessionCredentials) *kms.Client {
	return kms.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) CloudWatchLogsClient(creds SessionCredentials) *cloudwatchlogs.Client {
	return cloudwatchlogs.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) SecretsManagerClient(creds SessionCredentials) *secretsmanager.Client {
	return secretsmanager.NewFromConfig(f.awsConfig(creds))
}

func (f *ClientFactory) SSMClient(creds SessionCredentials) *ssm.Client {
	return ssm.NewFromConfig(f.awsConfig(creds))
}

// EC2ClientForRegion creates an EC2 client overriding the session region.
func (f *ClientFactory) EC2ClientForRegion(creds SessionCredentials, region string) *ec2.Client {
	c := creds
	c.Region = region
	return ec2.NewFromConfig(f.awsConfig(c))
}

// --- Convenience operations ---

// GetCallerIdentity performs sts:GetCallerIdentity.
func (f *ClientFactory) GetCallerIdentity(ctx context.Context, creds SessionCredentials) (arn, account, userID string, err error) {
	f.rateLimiter.Wait("sts")
	f.logAPICall("sts", "GetCallerIdentity", nil, nil)

	client := f.STSClient(creds)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		f.logAPICall("sts", "GetCallerIdentity", nil, err)
		return "", "", "", fmt.Errorf("GetCallerIdentity: %w", err)
	}
	return aws.ToString(result.Arn), aws.ToString(result.Account), aws.ToString(result.UserId), nil
}

// WaitForService blocks until the rate limit allows a call.
func (f *ClientFactory) WaitForService(service string) {
	f.rateLimiter.Wait(service)
}

// --- Rate Limiter ---

type RateLimiter struct {
	mu         sync.Mutex
	ratePerSec int
	lastCall   map[string]time.Time
}

func NewRateLimiter(ratePerSec int) *RateLimiter {
	return &RateLimiter{
		ratePerSec: ratePerSec,
		lastCall:   make(map[string]time.Time),
	}
}

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

// --- Response Cache ---

type cacheEntry struct {
	data      any
	expiresAt time.Time
}

// ResponseCache provides in-memory TTL caching for read-only AWS responses.
type ResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

func NewResponseCache(ttl time.Duration) *ResponseCache {
	return &ResponseCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached value. Returns nil and false if not found or expired.
func (c *ResponseCache) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

// Put stores a value in the cache.
func (c *ResponseCache) Put(key string, data any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = &cacheEntry{data: data, expiresAt: time.Now().Add(c.ttl)}
}

// Clear removes all entries, optionally filtering by key prefix.
func (c *ResponseCache) Clear(prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	if prefix == "" {
		count = len(c.entries)
		c.entries = make(map[string]*cacheEntry)
	} else {
		for k := range c.entries {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				delete(c.entries, k)
				count++
			}
		}
	}
	return count
}
