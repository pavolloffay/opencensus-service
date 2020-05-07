package tenantidprocessor

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"github.com/census-instrumentation/opencensus-service/receiver/jaegerreceiver"
	"github.com/uber/tchannel-go/thrift"
	"go.uber.org/zap"
	grpcmetadata "google.golang.org/grpc/metadata"
)

type tenantidprocessor struct {
	nextConsumer consumer.TraceConsumer
	logger       *zap.Logger
}

const (
	tenantIDHTTPHeaderKey = "x-tenant-id"
	tenantIDSpanTagKey    = "tenant-id"
)

// NewTraceProcessor reads the tenant ID from the HTTP/GRPC headers in the ctx and adds it to every span.
// If for whatever reason, we could not read the tenant ID, we return an error and drop
// the spans. Having this consumer enabled ensures that all spans that pass through are
// annotated with the tenant ID.
func NewTraceProcessor(nextConsumer consumer.TraceConsumer, logger *zap.Logger) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, errors.New("nextConsumer is nil")
	}

	return &tenantidprocessor{
		nextConsumer: nextConsumer,
		logger:       logger,
	}, nil
}

func (processor *tenantidprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	// Read the tenant ID from the headers
	tenantID := processor.readHeaderFromContext(ctx, tenantIDHTTPHeaderKey)

	if tenantID == "" {
		processor.logger.Warn(fmt.Sprintf("%s HTTP header not found. Dropping spans. TenantID not found.", tenantIDHTTPHeaderKey))
		return errors.New("Tenant ID not found in ctx argument passed in")
	}

	addTenantIDToSpans(td.Spans, tenantID)

	return processor.nextConsumer.ConsumeTraceData(ctx, td)
}

// tenantID should not be an empty string.
func addTenantIDToSpans(spans []*tracepb.Span, tenantID string) {
	for _, span := range spans {
		if span == nil {
			continue
		}

		if span.Attributes == nil {
			span.Attributes = &tracepb.Span_Attributes{
				AttributeMap: make(map[string]*tracepb.AttributeValue),
			}
		}

		if span.Attributes.AttributeMap == nil {
			span.Attributes.AttributeMap = make(map[string]*tracepb.AttributeValue)
		}

		addHeaderToSpanAttributes(span, tenantIDSpanTagKey, tenantID)
	}
}

func (processor *tenantidprocessor) readHeaderFromContext(ctx context.Context, headerName string) string {
	_, ok := ctx.(thrift.Context)
	if !ok { // Not thrift headers
		// Try GRPC for oc channel
		return processor.readHeaderFromGrpcContext(ctx, headerName)
	}

	thriftRequestHeadersKey := jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey)
	headers, ok := ctx.Value(thriftRequestHeadersKey).(http.Header)
	if !ok || headers == nil { // Should not happen since we put the headers in jaeger receiver http handler. Zipkin receiver should be disabled when this processor is turned on.
		processor.logger.Warn("Could not find " + jaegerreceiver.ThriftRequestHeadersKey + " in thrift.Context")
		return ""
	}

	return headers.Get(headerName)
}

func (processor *tenantidprocessor) readHeaderFromGrpcContext(ctx context.Context, headerName string) string {
	headers, ok := grpcmetadata.FromIncomingContext(ctx)
	if !ok {
		processor.logger.Warn("Could not read grpc metadata from the context")
		return ""
	}

	headerValues := headers[headerName]
	if headerValues == nil || len(headerValues) == 0 {
		processor.logger.Debug("No headers for " + headerName)
		return ""
	}

	return headerValues[0]
}

func addHeaderToSpanAttributes(span *tracepb.Span, headerKey string, headerValue string) {
	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: headerValue}}

	span.GetAttributes().AttributeMap[headerKey] = pbAttrib
}
