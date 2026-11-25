package privacy

import (
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/dlp/apiv2/dlppb"
)

type fakeDLPClient struct {
	called bool
}

func (f *fakeDLPClient) DeidentifyContent(_ context.Context, req *dlppb.DeidentifyContentRequest) (*dlppb.DeidentifyContentResponse, error) {
	f.called = true
	in := req.GetItem().GetValue()
	out := strings.ReplaceAll(in, "John Doe", "[PERSON_NAME]")
	return &dlppb.DeidentifyContentResponse{
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_Value{Value: out},
		},
	}, nil
}

func (f *fakeDLPClient) Close() error { return nil }

func TestHybridRedactorScrubsPIIAndInvokesCloudDLP(t *testing.T) {
	ctx := context.Background()
	fakeDLP := &fakeDLPClient{}
	r := NewHybridRedactorWithClient("acme-prod", fakeDLP)
	defer func() { _ = r.Close() }()

	raw := `user="John Doe" email=alice@example.com ip=10.24.1.9 ssn=123-45-6789 auth="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	got := r.RedactText(ctx, raw)

	if !fakeDLP.called {
		t.Fatal("expected Cloud DLP DeidentifyContent to be invoked")
	}
	if ContainsUnredactedPII(got) {
		t.Fatalf("expected all PII/tokens scrubbed, got: %s", got)
	}
	if !strings.Contains(got, "[PERSON_NAME]") {
		t.Fatalf("expected Cloud DLP entity replacement [PERSON_NAME], got: %s", got)
	}
}
