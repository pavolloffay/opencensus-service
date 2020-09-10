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

	encodedGrpcProtobuf := "AAAAADoKJVBhdHJpb3RzIFBhdGgsIE1lbmRoYW0sIE5KIDA3OTQ1LCBVU0ESEQiPvbzCARDt" +
		"/5qc/f////8BAAAAAD8KKjEwMSBOZXcgSmVyc2V5IDEwLCBXaGlwcGFueSwgTkogMDc5ODEsIFVTQRIRCLjrzcIBELXyn" +
		"Z39/////wEAAAAAMwoeVS5TLiA2LCBTaG9ob2xhLCBQQSAxODQ1OCwgVVNBEhEI/O2dxQEQ1Nzrmv3/////AQAAAAA8Ci" +
		"c1IENvbm5lcnMgUm9hZCwgS2luZ3N0b24sIE5ZIDEyNDAxLCBVU0ESEQi43qLIARDAqvue/f////8B"
	decodedGrpcProtobuf := `[{"1":"Patriots Path, Mendham, NJ 07945, USA","2":{"1":407838351,"2":18446744072963407853}},` +
		`{"1":"101 New Jersey 10, Whippany, NJ 07981, USA","2":{"1":408122808,"2":18446744072965552437}},` +
		`{"1":"U.S. 6, Shohola, PA 18458, USA","2":{"1":413628156,"2":18446744072960536148}},` +
		`{"1":"5 Conners Road, Kingston, NY 12401, USA","2":{"1":419999544,"2":18446744072969180480}}]`

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
								"rpc.system": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
								},
								"rpc.request.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.system": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
									},
									"rpc.request.body.base64": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
									},
									"rpc.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedGrpcProtobuf}},
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
								"rpc.system": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
								},
								"rpc.response.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.system": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
									},
									"rpc.response.body.base64": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
									},
									"rpc.response.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedGrpcProtobuf}},
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
								"rpc.system": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
								},
								"rpc.request.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.system": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
									},
									"rpc.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedGrpcProtobuf}},
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
								"rpc.system": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
								},
								"rpc.response.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.system": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
									},
									"rpc.response.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: decodedGrpcProtobuf}},
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
								"rpc.system": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
								},
								"rpc.response.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.system": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "grpc"}},
									},
									"rpc.response.body.base64": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "rpc_system_non_grpc",
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
								"rpc.system": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "wcf"}},
								},
								"rpc.response.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.system": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "wcf"}},
									},
									"rpc.response.body.base64": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no_rpc_system_defined",
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
								"rpc.response.body.base64": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
									"rpc.response.body.base64": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encodedGrpcProtobuf}},
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
				if strings.HasPrefix(s1.Value, "[") && strings.HasPrefix(s2.Value, "[") {
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
