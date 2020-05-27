package tenantidprocessor

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/census-instrumentation/opencensus-service/receiver/jaegerreceiver"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	tchanThrift "github.com/uber/tchannel-go/thrift"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	grpcmetadata "google.golang.org/grpc/metadata"
)

var testTenantID = "test-tenant-id"

func TestHeadersInThriftContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := make(http.Header)
	headers.Add(tenantIDHTTPHeaderKey, testTenantID)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	extractedTenantIDHeader := processor.readHeaderFromContext(ctx, tenantIDHTTPHeaderKey)
	gomega.Expect(extractedTenantIDHeader).Should(gomega.Equal(testTenantID))
}

func TestNoTenantIDHeaderInThriftContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := make(http.Header)
	headers.Add("foo", "bar")

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	extractedTenantIDHeader := processor.readHeaderFromContext(ctx, tenantIDHTTPHeaderKey)
	gomega.Expect(extractedTenantIDHeader).Should(gomega.Equal(""))
}

func TestNoThriftRequestHeadersInThriftCtx(t *testing.T) {
	gomega.RegisterTestingT(t)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := tchanThrift.Wrap(timeoutCtx)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	err = processor.ConsumeTraceData(ctx, testSpans)
	gomega.Expect(err).ShouldNot(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), []data.TraceData(nil)); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func TestHeadersInGrpcContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := map[string][]string{
		tenantIDHTTPHeaderKey: []string{testTenantID},
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := grpcmetadata.NewIncomingContext(timeoutCtx, headers)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	extractedTenantIDHeader := processor.readHeaderFromContext(ctx, tenantIDHTTPHeaderKey)
	gomega.Expect(extractedTenantIDHeader).Should(gomega.Equal(testTenantID))
}

func TestHeadersNoTenantIDInGrpcContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := map[string][]string{
		"foo": []string{"bar", "baz"},
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := grpcmetadata.NewIncomingContext(timeoutCtx, headers)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	extractedTenantIDHeader := processor.readHeaderFromContext(ctx, tenantIDHTTPHeaderKey)
	gomega.Expect(extractedTenantIDHeader).Should(gomega.Equal(""))
}

func TestHeadersSomeUnknownContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	extractedTenantIDHeader := processor.readHeaderFromContext(timeoutCtx, tenantIDHTTPHeaderKey)
	gomega.Expect(extractedTenantIDHeader).Should(gomega.Equal(""))
}

func testTenantIDFromHeaderAddedToSpans(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := make(http.Header)
	headers.Add(tenantIDHTTPHeaderKey, testTenantID)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	err = processor.ConsumeTraceData(ctx, testSpans)
	gomega.Expect(err).Should(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), expectedSpans); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func testTenantIDFromHeaderAddedToSpansWithoutAttributes(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := make(http.Header)
	headers.Add(tenantIDHTTPHeaderKey, testTenantID)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	err = processor.ConsumeTraceData(ctx, testSpansNoAttributes)
	gomega.Expect(err).Should(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), expectedSpansForNoAttributesSpans); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func testTenantIDFromHeaderAddedToSpansWithoutAttributesMap(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := make(http.Header)
	headers.Add(tenantIDHTTPHeaderKey, testTenantID)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	iProcessor, err := NewTraceProcessor(sinkExporter, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*tenantidprocessor)

	err = processor.ConsumeTraceData(ctx, testSpansNoAttributesMap)
	gomega.Expect(err).Should(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), expectedSpansForNoAttributesSpans); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func TestErrorNextConsumerIsNull(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := zap.New(zapcore.NewNopCore())
	iProcessor, err := NewTraceProcessor(nil, logger)

	gomega.Expect(err).ShouldNot(gomega.BeNil())
	gomega.Expect(iProcessor).Should(gomega.BeNil())
}
