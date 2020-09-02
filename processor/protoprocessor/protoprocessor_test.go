package protoprocessor

import (
	"context"
	"strings"
	"testing"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_protoprocessor_ConsumeTraceData(t *testing.T) {
	tr := true
	fl := false

	encodedProtobuf := "C7MB6xTjlQLklQLsFLQBDMO4AgiVmu86ZRXNWwfZBxXNWwcAAAAAkk0FaGVsbG/LgwZYlZrvOuVLFc1bB5mPPBXNWwcAAAAAkv+JLwdnb29kYnllzIMGxLgC"
	decodedProtobuf := `{"1":{"22":{"333":{"4444":{}}}},` +
		`"5000":{"1":123456789,"12":1.6535997e-34,"123":6.0995758e-316,"1234":"hello",` +
		`"12345":{"11":123456789,"1212":1.6535997e-34,"123123":6.0995758e-316,"12341234":"goodbye"}}}`

	tests := []struct {
		name string
		args ProtoDecoder
		td   data.TraceData
		want []data.TraceData
	}{
		{
			name: "decode_request_body_dont_strip",
			args: ProtoDecoder{
				Enabled:         &tr,
				StripEncodedTag: &fl,
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"grpc.request.body.encoded": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
								},
							},
						},
					},
				},
			},
			want: []data.TraceData{
				{
					Spans: []*tracepb.Span{
						{
							Name: &tracepb.TruncatableString{Value: "test"},
							Attributes: &tracepb.Span_Attributes{
								AttributeMap: map[string]*tracepb.AttributeValue{
									"grpc.request.body.encoded": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
									},
									"grpc.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "decode_response_body_dont_strip",
			args: ProtoDecoder{
				Enabled:         &tr,
				StripEncodedTag: &fl,
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"grpc.response.body.encoded": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
								},
							},
						},
					},
				},
			},
			want: []data.TraceData{
				{
					Spans: []*tracepb.Span{
						{
							Name: &tracepb.TruncatableString{Value: "test"},
							Attributes: &tracepb.Span_Attributes{
								AttributeMap: map[string]*tracepb.AttributeValue{
									"grpc.response.body.encoded": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
									},
									"grpc.response.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "decode_request_body_and_strip",
			args: ProtoDecoder{
				Enabled:         &tr,
				StripEncodedTag: &tr,
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"grpc.request.body.encoded": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
								},
							},
						},
					},
				},
			},
			want: []data.TraceData{
				{
					Spans: []*tracepb.Span{
						{
							Name: &tracepb.TruncatableString{Value: "test"},
							Attributes: &tracepb.Span_Attributes{
								AttributeMap: map[string]*tracepb.AttributeValue{
									"grpc.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "decode_response_body_and_strip",
			args: ProtoDecoder{
				Enabled:         &tr,
				StripEncodedTag: &tr,
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"grpc.response.body.encoded": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
								},
							},
						},
					},
				},
			},
			want: []data.TraceData{
				{
					Spans: []*tracepb.Span{
						{
							Name: &tracepb.TruncatableString{Value: "test"},
							Attributes: &tracepb.Span_Attributes{
								AttributeMap: map[string]*tracepb.AttributeValue{
									"grpc.response.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "disabled",
			args: ProtoDecoder{
				Enabled:         &fl,
				StripEncodedTag: &tr,
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"grpc.response.body.encoded": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
								},
							},
						},
					},
				},
			},
			want: []data.TraceData{
				{
					Spans: []*tracepb.Span{
						{
							Name: &tracepb.TruncatableString{Value: "test"},
							Attributes: &tracepb.Span_Attributes{
								AttributeMap: map[string]*tracepb.AttributeValue{
									"grpc.response.body.encoded": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	logger := zap.New(zapcore.NewNopCore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sinkExporter := &exportertest.SinkTraceExporter{}
			akp, err := NewTraceProcessor(sinkExporter, &tt.args, logger)
			if err != nil {
				t.Errorf("NewTraceProcessor() error = %v, want nil", err)
				return
			}

			if err := akp.ConsumeTraceData(context.Background(), tt.td); err != nil {
				t.Fatalf("ConsumeTraceData() error = %v, want nil", err)
			}

			gomega.RegisterTestingT(t)

			attributeStringValueCmpOpt := cmp.Comparer(func(s1, s2 *tracepb.TruncatableString) bool {
				if s1 == nil || s2 == nil {
					return cmp.Equal(s1, s2)
				}

				// Strings are JSON objects
				if strings.HasPrefix(s1.Value, "{") && strings.HasPrefix(s2.Value, "{") {
					return gomega.Expect(s1.Value).Should(gomega.MatchJSON(s2.Value))
				}

				return cmp.Equal(s1, s2)
			})

			if diff := cmp.Diff(sinkExporter.AllTraces(), tt.want, attributeStringValueCmpOpt); diff != "" {
				t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
			}
		})
	}
}
