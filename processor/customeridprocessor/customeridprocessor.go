package customeridprocessor

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
	"github.com/dgrijalva/jwt-go"
	"github.com/uber/tchannel-go/thrift"
	"go.uber.org/zap"
	grpcmetadata "google.golang.org/grpc/metadata"
)

type customeridprocessor struct {
	nextConsumer consumer.TraceConsumer
	logger       *zap.Logger
	secretKey    string
}

type CustomerIDReader struct {
	// Enabled when true will turn on this processor. (Is this necessary or will precense of this config denote being enabled?)
	Enabled bool `mapstructure:"enabled"`
	// Secret key for verifying JWT
	// TODO: This is definitely not secure. Once we settle down on which algo to use
	// for JWT signing and verification, we will figure out how to pass it in. We
	// can use k8s secret and map it to a volume
	SecretKey string `mapstructure:"secret-key"`
}

const (
	customerIDJwtTokenHTTPHeaderKey = "x-traceable-customer-id"
	customerIDFieldKey              = "customer_id"
	customerIDSpanTagKey            = "traceable.customer_id"
)

func NewTraceProcessor(nextConsumer consumer.TraceConsumer, customerIDReader *CustomerIDReader, logger *zap.Logger) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, errors.New("nextConsumer is nil")
	}

	if secretKeyIsValid(customerIDReader.SecretKey) {
		return nil, errors.New("invalid secret key")
	}

	return &customeridprocessor{
		nextConsumer: nextConsumer,
		logger:       logger,
		secretKey:    customerIDReader.SecretKey,
	}, nil
}

func (processor *customeridprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	// Read jwt header from the context, verify and extract the customer id.
	customerID := ""
	customerIDJwtTokenHeader := processor.readHeaderFromContext(ctx, customerIDJwtTokenHTTPHeaderKey)
	if customerIDJwtTokenHeader == "" {
		processor.logger.Warn(fmt.Sprintf("%s HTTP header not found.", customerIDJwtTokenHTTPHeaderKey))
	} else {
		customerID = processor.readCustomerIDFromJwtToken(customerIDJwtTokenHeader, processor.secretKey)
		if customerID == "" {
			processor.logger.Warn("Customer ID was not found in the jwt token header.")
		}
	}

	if customerID == "" {
		processor.logger.Warn("Dropping spans. CustomerID not found.")
		return errors.New("Customer ID not found in ctx argument passed in")
	}

	addCustomerIDToSpans(td.Spans, customerID)

	return processor.nextConsumer.ConsumeTraceData(ctx, td)
}

// customerID should not be an empty string.
func addCustomerIDToSpans(spans []*tracepb.Span, customerID string) {
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

		addHeaderToSpanAttributes(span, customerIDSpanTagKey, customerID)
	}
}

func (processor *customeridprocessor) readHeaderFromContext(ctx context.Context, headerName string) string {
	_, ok := ctx.(thrift.Context)
	if !ok { // Not thrift headers
		// Try GRPC for oc channel
		return processor.readHeaderFromGrpcContext(ctx, headerName)
	}

	thriftRequestHeadersKey := jaegerreceiver.ThriftRequestHeaders(jaegerreceiver.ThriftRequestHeadersKey)
	headers := ctx.Value(thriftRequestHeadersKey).(http.Header)
	if headers == nil { // Should not happen since we put the headers in jaeger receiver http handler. Zipkin receiver should be disabled when this processor is turned on.
		processor.logger.Warn("Could not find " + jaegerreceiver.ThriftRequestHeadersKey + " in thrift.Context")
		return ""
	}

	return headers.Get(headerName)
}

func (processor *customeridprocessor) readHeaderFromGrpcContext(ctx context.Context, headerName string) string {
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

func (processor *customeridprocessor) readCustomerIDFromJwtToken(customerIDJwtTokenHeader string, secretKey string) string {
	// 1. Verify integrity of jwt token
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(customerIDJwtTokenHeader, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// Return the []byte containing your secret, i.e. []byte("my_secret_key")
		return []byte(secretKey), nil
	})

	if err != nil {
		processor.logger.Error("An error while parsing and verifying customerID jwt token", zap.Error(err))
		return ""
	}

	if !token.Valid {
		processor.logger.Error("Invalid customerID jwt token")
		return ""
	}

	// 2. Read the "customer_id" field from the decoded token
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		customerIDVal, ok := claims[string(customerIDFieldKey)].(string)
		if !ok {
			processor.logger.Error("customerID field not found in jwt token")
			return ""
		}

		return customerIDVal
	}

	processor.logger.Error("Failed to type cast claims to jwt.MapClaims")
	return ""
}

func addHeaderToSpanAttributes(span *tracepb.Span, headerKey string, headerValue string) {
	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: headerValue}}

	span.GetAttributes().AttributeMap[headerKey] = pbAttrib
}

// Verify that this is the secret key we want
func secretKeyIsValid(secretKey string) bool {
	// For now just check the length
	return len(secretKey) == 0
}
