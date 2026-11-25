// Package privacy scrubs Personally Identifiable Information (PII), credentials,
// and sensitive telemetry tokens from logs, tool outputs, and memory entries
// using Google Cloud Sensitive Data Protection (DLP) plus deterministic regex shields.
package privacy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
)

// Redactor scrubs sensitive tokens and PII from unstructured text and structured maps.
type Redactor interface {
	RedactText(ctx context.Context, input string) string
	RedactAny(ctx context.Context, val any) any
	Close() error
}

// DLPDeidentifier abstracts Cloud DLP's DeidentifyContent RPC for unit testing.
type DLPDeidentifier interface {
	DeidentifyContent(ctx context.Context, req *dlppb.DeidentifyContentRequest) (*dlppb.DeidentifyContentResponse, error)
	Close() error
}

type liveDLPClient struct {
	client *dlp.Client
}

func (c *liveDLPClient) DeidentifyContent(ctx context.Context, req *dlppb.DeidentifyContentRequest) (*dlppb.DeidentifyContentResponse, error) {
	return c.client.DeidentifyContent(ctx, req)
}

func (c *liveDLPClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

var (
	jwtPattern        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	bearerPattern     = regexp.MustCompile(`(?i)\b(bearer|token|api[_-]?key|password|secret)\s*[:=]\s*([^\s"',;]+)`)
	authHeaderPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`)
	gcpAPIKeyPattern  = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
	ghTokenPattern    = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`)
	emailPattern      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	ssnPattern        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	phonePattern      = regexp.MustCompile(`(?:\+\d{1,3}[-.\s]?)?\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b|\+\d{1,3}[-.\s]\d{2,4}[-.\s]\d{3,4}[-.\s]\d{3,4}\b`)
	ipv4Pattern       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	sensitiveKeyNames = map[string]struct{}{
		"password":      {},
		"secret":        {},
		"token":         {},
		"api_key":       {},
		"apikey":        {},
		"authorization": {},
		"client_secret": {},
		"private_key":   {},
	}
)

// HybridRedactor applies fast local regex scrubbing first and optionally invokes
// Google Cloud Sensitive Data Protection (DLP) for deep entity de-identification.
type HybridRedactor struct {
	projectID string
	dlpClient DLPDeidentifier
}

// NewHybridRedactor constructs a Redactor backed by local deterministic rules and,
// when enableCloudDLP and projectID are set, Google Cloud DLP API.
func NewHybridRedactor(ctx context.Context, projectID string, enableCloudDLP bool) (*HybridRedactor, error) {
	r := &HybridRedactor{projectID: strings.TrimSpace(projectID)}
	if enableCloudDLP && r.projectID != "" {
		c, err := dlp.NewClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("initializing cloud dlp client: %w", err)
		}
		r.dlpClient = &liveDLPClient{client: c}
	}
	return r, nil
}

// NewHybridRedactorWithClient injects a custom DLPDeidentifier (used in tests).
func NewHybridRedactorWithClient(projectID string, client DLPDeidentifier) *HybridRedactor {
	return &HybridRedactor{
		projectID: strings.TrimSpace(projectID),
		dlpClient: client,
	}
}

// RedactText scrubs credentials, emails, tokens, SSNs, phone numbers, and IPs,
// then runs Cloud DLP inspection/replacement when configured.
func (r *HybridRedactor) RedactText(ctx context.Context, input string) string {
	if input == "" {
		return ""
	}
	scrubbed := scrubDeterministic(input)
	if r == nil || r.dlpClient == nil || r.projectID == "" {
		return scrubbed
	}

	req := &dlppb.DeidentifyContentRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", r.projectID),
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes: []*dlppb.InfoType{
				{Name: "EMAIL_ADDRESS"},
				{Name: "PHONE_NUMBER"},
				{Name: "PERSON_NAME"},
				{Name: "CREDIT_CARD_NUMBER"},
				{Name: "US_SOCIAL_SECURITY_NUMBER"},
				{Name: "IP_ADDRESS"},
				{Name: "AUTH_TOKEN"},
				{Name: "JSON_WEB_TOKEN"},
				{Name: "GCP_API_KEY"},
			},
			MinLikelihood: dlppb.Likelihood_LIKELIHOOD_UNSPECIFIED,
		},
		DeidentifyConfig: &dlppb.DeidentifyConfig{
			Transformation: &dlppb.DeidentifyConfig_InfoTypeTransformations{
				InfoTypeTransformations: &dlppb.InfoTypeTransformations{
					Transformations: []*dlppb.InfoTypeTransformations_InfoTypeTransformation{
						{
							PrimitiveTransformation: &dlppb.PrimitiveTransformation{
								Transformation: &dlppb.PrimitiveTransformation_ReplaceWithInfoTypeConfig{
									ReplaceWithInfoTypeConfig: &dlppb.ReplaceWithInfoTypeConfig{},
								},
							},
						},
					},
				},
			},
		},
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_Value{Value: scrubbed},
		},
	}

	resp, err := r.dlpClient.DeidentifyContent(ctx, req)
	if err != nil || resp.GetItem() == nil {
		// Fail safe: retain deterministic local redaction when Cloud DLP RPC fails.
		return scrubbed
	}
	return resp.GetItem().GetValue()
}

// RedactAny recursively sanitizes maps, slices, and string values before logging or persistence.
func (r *HybridRedactor) RedactAny(ctx context.Context, val any) any {
	switch v := val.(type) {
	case string:
		return r.RedactText(ctx, v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, elem := range v {
			if _, sensitive := sensitiveKeyNames[strings.ToLower(strings.TrimSpace(k))]; sensitive {
				out[k] = "[REDACTED_SECRET]"
				continue
			}
			out[k] = r.RedactAny(ctx, elem)
		}
		return out
	case []string:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = r.RedactText(ctx, s)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			out[i] = r.RedactAny(ctx, elem)
		}
		return out
	default:
		return val
	}
}

// Close releases any underlying Cloud DLP client connection.
func (r *HybridRedactor) Close() error {
	if r == nil || r.dlpClient == nil {
		return nil
	}
	return r.dlpClient.Close()
}

// ContainsUnredactedPII checks whether text still contains recognizable raw PII or tokens.
func ContainsUnredactedPII(text string) bool {
	if text == "" {
		return false
	}
	return jwtPattern.MatchString(text) ||
		gcpAPIKeyPattern.MatchString(text) ||
		ghTokenPattern.MatchString(text) ||
		authHeaderPattern.MatchString(text) ||
		emailPattern.MatchString(text) ||
		ssnPattern.MatchString(text)
}

func scrubDeterministic(s string) string {
	s = jwtPattern.ReplaceAllString(s, "[REDACTED_JWT]")
	s = gcpAPIKeyPattern.ReplaceAllString(s, "[REDACTED_GCP_KEY]")
	s = ghTokenPattern.ReplaceAllString(s, "[REDACTED_TOKEN]")
	s = authHeaderPattern.ReplaceAllString(s, "Bearer [REDACTED_TOKEN]")
	s = bearerPattern.ReplaceAllString(s, "${1}=[REDACTED_SECRET]")
	s = emailPattern.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = ssnPattern.ReplaceAllString(s, "[REDACTED_SSN]")
	s = phonePattern.ReplaceAllString(s, "[REDACTED_PHONE]")
	s = ipv4Pattern.ReplaceAllStringFunc(s, func(ip string) string {
		// Preserve localhost loopback indicator only when needed for local bind diagnostics;
		// scrub all pod/customer/node IPv4 addresses.
		if ip == "127.0.0.1" {
			return ip
		}
		return "[REDACTED_IP]"
	})
	return s
}
