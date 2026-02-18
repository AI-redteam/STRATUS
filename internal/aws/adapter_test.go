package aws

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestResponseCache_PutGet(t *testing.T) {
	cache := NewResponseCache(1 * time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key2", 42)

	v, ok := cache.Get("key1")
	if !ok || v != "value1" {
		t.Fatalf("expected 'value1', got %v (ok=%v)", v, ok)
	}

	v, ok = cache.Get("key2")
	if !ok || v != 42 {
		t.Fatalf("expected 42, got %v (ok=%v)", v, ok)
	}
}

func TestResponseCache_Miss(t *testing.T) {
	cache := NewResponseCache(1 * time.Minute)

	_, ok := cache.Get("nonexistent")
	if ok {
		t.Fatal("expected cache miss for nonexistent key")
	}
}

func TestResponseCache_Expiry(t *testing.T) {
	cache := NewResponseCache(1 * time.Millisecond)

	cache.Put("key1", "value1")
	time.Sleep(5 * time.Millisecond)

	_, ok := cache.Get("key1")
	if ok {
		t.Fatal("expected cache miss for expired key")
	}
}

func TestResponseCache_ClearAll(t *testing.T) {
	cache := NewResponseCache(1 * time.Minute)

	cache.Put("a:1", "v1")
	cache.Put("b:2", "v2")
	cache.Put("a:3", "v3")

	n := cache.Clear("")
	if n != 3 {
		t.Fatalf("expected 3 cleared, got %d", n)
	}

	_, ok := cache.Get("a:1")
	if ok {
		t.Fatal("expected cache empty after clear")
	}
}

func TestResponseCache_ClearPrefix(t *testing.T) {
	cache := NewResponseCache(1 * time.Minute)

	cache.Put("iam:users:abc", "users")
	cache.Put("iam:roles:abc", "roles")
	cache.Put("s3:buckets:abc", "buckets")
	cache.Put("ec2:instances:abc", "instances")

	n := cache.Clear("iam:")
	if n != 2 {
		t.Fatalf("expected 2 cleared with prefix 'iam:', got %d", n)
	}

	// IAM entries should be gone
	_, ok := cache.Get("iam:users:abc")
	if ok {
		t.Fatal("expected iam:users entry cleared")
	}

	// S3 and EC2 entries should remain
	v, ok := cache.Get("s3:buckets:abc")
	if !ok || v != "buckets" {
		t.Fatal("expected s3 entry to remain")
	}
	v, ok = cache.Get("ec2:instances:abc")
	if !ok || v != "instances" {
		t.Fatal("expected ec2 entry to remain")
	}
}

func TestRateLimiter_Sequencing(t *testing.T) {
	rl := NewRateLimiter(100) // 100 req/s = 10ms interval

	start := time.Now()
	rl.Wait("test-svc")
	rl.Wait("test-svc")
	elapsed := time.Since(start)

	// Second call should have waited ~10ms
	if elapsed < 5*time.Millisecond {
		t.Fatalf("expected rate limiter to enforce delay, elapsed: %v", elapsed)
	}
}

func TestRateLimiter_DifferentServices(t *testing.T) {
	rl := NewRateLimiter(10) // 10 req/s = 100ms interval

	start := time.Now()
	rl.Wait("svc-a")
	rl.Wait("svc-b") // Different service, should not wait
	elapsed := time.Since(start)

	// Should be nearly instant since different services
	if elapsed > 50*time.Millisecond {
		t.Fatalf("expected no delay for different services, elapsed: %v", elapsed)
	}
}

func TestNewClientFactory(t *testing.T) {
	logger := noopLogger()
	factory := NewClientFactory(logger)

	if factory.cache == nil {
		t.Fatal("expected cache to be initialized")
	}
	if factory.rateLimiter == nil {
		t.Fatal("expected rate limiter to be initialized")
	}
}

func TestNewClientFactoryWithRate(t *testing.T) {
	logger := noopLogger()
	factory := NewClientFactoryWithRate(logger, 50, 10*time.Minute)

	if factory.cache == nil {
		t.Fatal("expected cache to be initialized")
	}
	if factory.rateLimiter.ratePerSec != 50 {
		t.Fatalf("expected rate 50, got %d", factory.rateLimiter.ratePerSec)
	}
}

func TestClientFactory_ClientCreation(t *testing.T) {
	logger := noopLogger()
	factory := NewClientFactory(logger)
	creds := SessionCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "",
		Region:          "us-east-1",
	}

	// Verify all client factories return non-nil clients
	if factory.STSClient(creds) == nil {
		t.Fatal("STSClient returned nil")
	}
	if factory.IAMClient(creds) == nil {
		t.Fatal("IAMClient returned nil")
	}
	if factory.S3Client(creds) == nil {
		t.Fatal("S3Client returned nil")
	}
	if factory.EC2Client(creds) == nil {
		t.Fatal("EC2Client returned nil")
	}
	if factory.LambdaClient(creds) == nil {
		t.Fatal("LambdaClient returned nil")
	}
	if factory.CloudTrailClient(creds) == nil {
		t.Fatal("CloudTrailClient returned nil")
	}
	if factory.KMSClient(creds) == nil {
		t.Fatal("KMSClient returned nil")
	}
	if factory.CloudWatchLogsClient(creds) == nil {
		t.Fatal("CloudWatchLogsClient returned nil")
	}
	if factory.SecretsManagerClient(creds) == nil {
		t.Fatal("SecretsManagerClient returned nil")
	}
	if factory.SSMClient(creds) == nil {
		t.Fatal("SSMClient returned nil")
	}
	if factory.EC2ClientForRegion(creds, "eu-west-1") == nil {
		t.Fatal("EC2ClientForRegion returned nil")
	}
}

func TestSafeTimePtr(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	result := safeTimePtr(&now)
	if result != "2025-06-15 10:30" {
		t.Fatalf("expected '2025-06-15 10:30', got '%s'", result)
	}

	result = safeTimePtr(nil)
	if result != "" {
		t.Fatalf("expected empty string for nil, got '%s'", result)
	}
}

func noopLogger() zerolog.Logger {
	return zerolog.Nop()
}
