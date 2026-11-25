package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.36.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/adk/v2/telemetry"
)

const (
	ServiceName    = "kubeguard-agent"
	ServiceVersion = "1.0.0"
)

// TelemetryRuntime manages OpenTelemetry providers for ADK and KubeGuard subsystems.
type TelemetryRuntime struct {
	Providers   *telemetry.Providers
	Resource    *resource.Resource
	ADKOptions  []telemetry.Option
	localTracer *sdktrace.TracerProvider
}

// InitTelemetry configures OpenTelemetry distributed tracing for ADK runs,
// sub-agent fan-out, DLP scrubbing, and Kubernetes tool calls.
func InitTelemetry(ctx context.Context, enableCloudExport bool, extraExporters ...sdktrace.SpanExporter) (*TelemetryRuntime, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(ServiceName),
			semconv.ServiceVersionKey.String(ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating otel resource: %w", err)
	}

	opts := []telemetry.Option{
		telemetry.WithResource(res),
	}
	if enableCloudExport {
		opts = append(opts, telemetry.WithOtelToCloud(true))
	}

	var spanProcessors []sdktrace.SpanProcessor
	for _, exp := range extraExporters {
		if exp != nil {
			proc := sdktrace.NewSimpleSpanProcessor(exp)
			spanProcessors = append(spanProcessors, proc)
			opts = append(opts, telemetry.WithSpanProcessors(proc))
		}
	}

	// When custom exporters (e.g. in-memory test span recorder) are supplied in unit/eval tests,
	// also install a local SDK TracerProvider on the global OTel registry while keeping
	// ADKOptions compatible with webLauncher's SpanProcessor registration.
	if len(spanProcessors) > 0 || !enableCloudExport {
		var tpOpts []sdktrace.TracerProviderOption
		tpOpts = append(tpOpts, sdktrace.WithResource(res))
		for _, proc := range spanProcessors {
			tpOpts = append(tpOpts, sdktrace.WithSpanProcessor(proc))
		}
		tp := sdktrace.NewTracerProvider(tpOpts...)
		otel.SetTracerProvider(tp)
		return &TelemetryRuntime{
			Resource:    res,
			ADKOptions:  opts,
			localTracer: tp,
		}, nil
	}

	providers, err := telemetry.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing adk telemetry providers: %w", err)
	}
	providers.SetGlobalOtelProviders()

	return &TelemetryRuntime{
		Providers:  providers,
		Resource:   res,
		ADKOptions: opts,
	}, nil
}

// Tracer returns a named OpenTelemetry tracer from the global provider.
func Tracer(component string) trace.Tracer {
	return otel.Tracer("github.com/leo-hoet/kubeguard/" + component)
}

// Shutdown flushes pending spans and metrics cleanly.
func (t *TelemetryRuntime) Shutdown(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if t.Providers != nil {
		return t.Providers.Shutdown(ctx)
	}
	if t.localTracer != nil {
		return t.localTracer.Shutdown(ctx)
	}
	return nil
}
