package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awscreds "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// RawAPIRequest describes an arbitrary AWS API request.
type RawAPIRequest struct {
	Service string
	Action  string
	Region  string
	Params  map[string]any
	Creds   SessionCredentials
}

// ExecuteRawRequest signs and sends an arbitrary AWS API request using SigV4.
func ExecuteRawRequest(ctx context.Context, req RawAPIRequest) (string, int, error) {
	endpoint := resolveEndpoint(req.Service, req.Region)

	// Build query-string body
	body := fmt.Sprintf("Action=%s", req.Action)
	if needsVersion(req.Service) {
		body += "&Version=" + apiVersion(req.Service)
	}
	for k, v := range req.Params {
		body += fmt.Sprintf("&%s=%v", k, v)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Hash the body for SigV4
	h := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(h[:])

	signer := v4.NewSigner()
	creds := awscreds.Credentials{
		AccessKeyID:     req.Creds.AccessKeyID,
		SecretAccessKey: req.Creds.SecretAccessKey,
		SessionToken:    req.Creds.SessionToken,
	}

	signingName := sigV4ServiceName(req.Service)
	signingRegion := req.Region
	if isGlobalService(req.Service) {
		signingRegion = "us-east-1"
	}

	if err := signer.SignHTTP(ctx, creds, httpReq, payloadHash, signingName, signingRegion, time.Now()); err != nil {
		return "", 0, fmt.Errorf("signing request: %w", err)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	return string(respBody), resp.StatusCode, nil
}

func resolveEndpoint(service, region string) string {
	switch strings.ToLower(service) {
	case "iam":
		return "https://iam.amazonaws.com"
	case "sts":
		return fmt.Sprintf("https://sts.%s.amazonaws.com", region)
	case "s3":
		return fmt.Sprintf("https://s3.%s.amazonaws.com", region)
	case "organizations":
		return "https://organizations.us-east-1.amazonaws.com"
	default:
		return fmt.Sprintf("https://%s.%s.amazonaws.com", service, region)
	}
}

func sigV4ServiceName(service string) string {
	switch strings.ToLower(service) {
	case "cloudwatchlogs", "logs":
		return "logs"
	case "secretsmanager":
		return "secretsmanager"
	default:
		return strings.ToLower(service)
	}
}

func isGlobalService(service string) bool {
	switch strings.ToLower(service) {
	case "iam", "organizations":
		return true
	default:
		return false
	}
}

func needsVersion(service string) bool {
	switch strings.ToLower(service) {
	case "iam", "sts", "ec2", "cloudtrail":
		return true
	default:
		return false
	}
}

func apiVersion(service string) string {
	switch strings.ToLower(service) {
	case "iam":
		return "2010-05-08"
	case "sts":
		return "2011-06-15"
	case "ec2":
		return "2016-11-15"
	case "cloudtrail":
		return "2013-11-01"
	default:
		return "2012-11-05"
	}
}
