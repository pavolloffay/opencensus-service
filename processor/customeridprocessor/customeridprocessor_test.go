package customeridprocessor

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/census-instrumentation/opencensus-service/receiver/jaegerreceiver"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	tchanThrift "github.com/uber/tchannel-go/thrift"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	grpcmetadata "google.golang.org/grpc/metadata"
)

var testSecret = "super-awesome-great-strong-secret-key"
var testCustomerID = "test-customer-id"

func TestSuccessfulCustomerIDReadingFromJwtToken(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: testCustomerID,
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerID := processor.readCustomerIDFromJwtToken(tokenString, testSecret)
	gomega.Expect(extractedCustomerID).Should(gomega.Equal(testCustomerID))
}

func TestFailedCustomerIDReadingFromJwtTokenWrongKey(t *testing.T) {
	gomega.RegisterTestingT(t)
	signingKey := "different-key"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: testCustomerID,
	})
	tokenString, err := token.SignedString([]byte(signingKey))

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerID := processor.readCustomerIDFromJwtToken(tokenString, testSecret)
	gomega.Expect(extractedCustomerID).Should(gomega.Equal(""))
}

func TestFailedCustomerIDReadingFromJwtTokenNoCustomerID(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerID := processor.readCustomerIDFromJwtToken(tokenString, testSecret)
	gomega.Expect(extractedCustomerID).Should(gomega.Equal(""))
}

func TestFailedCustomerIDReadingFromJwtTokenCustomerIDNotString(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: 2322442,
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerID := processor.readCustomerIDFromJwtToken(tokenString, testSecret)
	gomega.Expect(extractedCustomerID).Should(gomega.Equal(""))
}

func TestHeadersInThriftContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	testCustomerIDToken := "test-customer-id-token"

	headers := make(http.Header)
	headers.Add(customerIDJwtTokenHTTPHeaderKey, testCustomerIDToken)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerIDHeader := processor.readHeaderFromContext(ctx, customerIDJwtTokenHTTPHeaderKey)
	gomega.Expect(extractedCustomerIDHeader).Should(gomega.Equal(testCustomerIDToken))
}

func TestNoCustomerIDHeaderInThriftContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := make(http.Header)
	headers.Add("foo", "bar")

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerIDHeader := processor.readHeaderFromContext(ctx, customerIDJwtTokenHTTPHeaderKey)
	gomega.Expect(extractedCustomerIDHeader).Should(gomega.Equal(""))
}

func TestHeadersInGrpcContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	testCustomerIDToken := "test-customer-id-token"

	headers := map[string][]string{
		customerIDJwtTokenHTTPHeaderKey: []string{testCustomerIDToken},
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := grpcmetadata.NewIncomingContext(timeoutCtx, headers)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerIDHeader := processor.readHeaderFromContext(ctx, customerIDJwtTokenHTTPHeaderKey)
	gomega.Expect(extractedCustomerIDHeader).Should(gomega.Equal(testCustomerIDToken))
}

func TestHeadersNoCustomerIDInGrpcContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	headers := map[string][]string{
		"foo": []string{"bar", "baz"},
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := grpcmetadata.NewIncomingContext(timeoutCtx, headers)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerIDHeader := processor.readHeaderFromContext(ctx, customerIDJwtTokenHTTPHeaderKey)
	gomega.Expect(extractedCustomerIDHeader).Should(gomega.Equal(""))
}

func TestHeadersSomeUnknownContext(t *testing.T) {
	gomega.RegisterTestingT(t)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	extractedCustomerIDHeader := processor.readHeaderFromContext(timeoutCtx, customerIDJwtTokenHTTPHeaderKey)
	gomega.Expect(extractedCustomerIDHeader).Should(gomega.Equal(""))
}

func TestCustomerIDFromHeaderAddedToSpans(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: testCustomerID,
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	headers := make(http.Header)
	headers.Add(customerIDJwtTokenHTTPHeaderKey, tokenString)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	err = processor.ConsumeTraceData(ctx, testSpans)
	gomega.Expect(err).Should(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), expectedSpans); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func TestCustomerIDFromHeaderAddedToSpansWithoutAttributes(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: testCustomerID,
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	headers := make(http.Header)
	headers.Add(customerIDJwtTokenHTTPHeaderKey, tokenString)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	err = processor.ConsumeTraceData(ctx, testSpansNoAttributes)
	gomega.Expect(err).Should(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), expectedSpansForNoAttributesSpans); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func TestCustomerIDFromHeaderAddedToSpansWithoutAttributesMap(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: testCustomerID,
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	headers := make(http.Header)
	headers.Add(customerIDJwtTokenHTTPHeaderKey, tokenString)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctxWithRequestHeaders := context.WithValue(timeoutCtx, jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey), headers)
	ctx := tchanThrift.Wrap(ctxWithRequestHeaders)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	err = processor.ConsumeTraceData(ctx, testSpansNoAttributesMap)
	gomega.Expect(err).Should(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), expectedSpansForNoAttributesSpans); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func TestErrorWhenGettingCustomerIDFromCtx(t *testing.T) {
	gomega.RegisterTestingT(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		customerIDFieldKey: testCustomerID,
	})
	tokenString, err := token.SignedString([]byte(testSecret))

	headers := make(http.Header)
	headers.Add(customerIDJwtTokenHTTPHeaderKey, tokenString)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)
	gomega.Expect(err).Should(gomega.BeNil())

	processor := iProcessor.(*customeridprocessor)

	err = processor.ConsumeTraceData(ctx, testSpans)
	gomega.Expect(err).ShouldNot(gomega.BeNil())

	if diff := cmp.Diff(sinkExporter.AllTraces(), []data.TraceData(nil)); diff != "" {
		t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
	}
}

func TestErrorSecretKeyIsInvalid(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := zap.New(zapcore.NewNopCore())
	sinkExporter := &exportertest.SinkTraceExporter{}
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: ""}
	iProcessor, err := NewTraceProcessor(sinkExporter, customerIDReader, logger)

	gomega.Expect(err).ShouldNot(gomega.BeNil())
	gomega.Expect(iProcessor).Should(gomega.BeNil())
}

func TestErrorNextConsumerIsNull(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := zap.New(zapcore.NewNopCore())
	customerIDReader := &CustomerIDReader{Enabled: true, SecretKey: testSecret}
	iProcessor, err := NewTraceProcessor(nil, customerIDReader, logger)

	gomega.Expect(err).ShouldNot(gomega.BeNil())
	gomega.Expect(iProcessor).Should(gomega.BeNil())
}
