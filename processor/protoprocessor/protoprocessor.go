package protoprocessor

import (
	"context"
	b64 "encoding/base64"
	"errors"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"

	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"github.com/census-instrumentation/opencensus-service/processor/protoprocessor/decoder"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

const (
	rpcSystemTag              = "rpc.system"
	rpcSystemTagGrpcValue     = "grpc"
	rpcRequestBodyTag         = "rpc.request.body"
	rpcResponseBodyTag        = "rpc.response.body"
	rpcRequestBodyEncodedTag  = rpcRequestBodyTag + ".base64"
	rpcResponseBodyEncodedTag = rpcResponseBodyTag + ".base64"
	rpcBodyDecodeRawTag       = "rpc.body.decode_raw"
)

// Protodecoder defines configuration for protoprocessor
type ProtoDecoder struct {
	Enabled         *bool `mapstructure:"enabled,omitempty"`
	StripEncodedTag *bool `mapstructure:"strip-encoded-tag,omitempty"`
}

type protoprocessor struct {
	nextConsumer    consumer.TraceConsumer
	logger          *zap.Logger
	stripEncodedTag bool
	enabled         bool
	tagMap          map[string]string
	grpcDecoder     *decoder.Grpcdecoder
}

// NewTraceProcessor returns a protoprocessor
func NewTraceProcessor(nextConsumer consumer.TraceConsumer, protoDecoder *ProtoDecoder, logger *zap.Logger) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, errors.New("nextConsumer is nil")
	}
	enabled := false
	if protoDecoder.Enabled != nil {
		enabled = *protoDecoder.Enabled
	}

	stripEncodedTag := true
	if protoDecoder.StripEncodedTag != nil {
		stripEncodedTag = *protoDecoder.StripEncodedTag
	}
	tagMap := make(map[string]string)
	tagMap[rpcRequestBodyEncodedTag] = rpcRequestBodyTag
	tagMap[rpcResponseBodyEncodedTag] = rpcResponseBodyTag

	return &protoprocessor{
		nextConsumer:    nextConsumer,
		logger:          logger,
		enabled:         enabled,
		stripEncodedTag: stripEncodedTag,
		tagMap:          tagMap,
		grpcDecoder:     decoder.NewGrpcDecoder(logger),
	}, nil
}

func (processor *protoprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	if !processor.enabled {
		return processor.nextConsumer.ConsumeTraceData(ctx, td)
	}
	for _, span := range td.Spans {
		if span == nil || span.Attributes == nil {
			continue
		}
		attribMap := span.Attributes.AttributeMap
		if len(attribMap) == 0 {
			continue
		}

		if value, ok := span.Attributes.AttributeMap[rpcSystemTag]; !ok || value.GetStringValue().Value != rpcSystemTagGrpcValue {
			continue
		}

		decodedAttributes := make(map[string]string)
		for key, value := range span.Attributes.AttributeMap {
			if value.GetStringValue() == nil {
				continue
			}
			if _, ok := processor.tagMap[key]; ok {
				processor.processValue(key, value, decodedAttributes)
			}
		}
		for key, decodedValue := range decodedAttributes {
			processor.updateDecodedValue(span, key, decodedValue)
		}
		if len(decodedAttributes) > 0 {
			processor.addAttribute(span, rpcBodyDecodeRawTag, "true")
		}
	}

	return processor.nextConsumer.ConsumeTraceData(ctx, td)
}

func (processor *protoprocessor) processValue(key string, value *tracepb.AttributeValue, decodedAttributes map[string]string) {
	// Decode the value in this case
	tagValue := value.GetStringValue().Value
	raw, err := b64.StdEncoding.DecodeString(tagValue)
	if err != nil {
		processor.logger.Debug("Unable to decode value for key", zap.String("key", key), zap.String("value", tagValue))
		return
	}
	decodedMsg, parsedLen := processor.grpcDecoder.Decode(raw)
	if parsedLen < 0 {
		processor.logger.Debug("Error while parsing message", zap.Int("erro code", parsedLen))
		return
	}
	decodedMsgJson, err := jsoniter.MarshalToString(decodedMsg)
	if err != nil {
		processor.logger.Debug("Error while creating json", zap.Error(err))
		return
	}
	decodedAttributes[key] = decodedMsgJson
}

func (processor *protoprocessor) updateDecodedValue(span *tracepb.Span, key string, decodedValue string) {
	decodedKey, ok := processor.tagMap[key]
	if !ok {
		processor.logger.Debug("Unknown key decoded", zap.String("key", key), zap.String("value", decodedValue))
		return
	}

	processor.addAttribute(span, decodedKey, decodedValue)

	if processor.stripEncodedTag {
		if _, ok := span.GetAttributes().AttributeMap[key]; ok {
			delete(span.GetAttributes().AttributeMap, key)
		}
	}
}

func (processor *protoprocessor) addAttribute(span *tracepb.Span, key string, value string) {
	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: value}}
	span.GetAttributes().AttributeMap[key] = pbAttrib
}
