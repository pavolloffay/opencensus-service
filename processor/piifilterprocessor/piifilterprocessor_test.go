package piifilterprocessor

import (
	"context"
	"fmt"
	"testing"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/sha3"
)

func Test_piifilterprocessor_ConsumeTraceData(t *testing.T) {

	h := make([]byte, 64)
	sha3.ShakeSum256(h, []byte("abc123"))
	sha3Abc123 := fmt.Sprintf("%x", h)

	jsonInput := []byte(`{  
  "a":"aaa",
  "password":"root_pw",
  "b":{  
    "b_1":"bbb",
    "password":"nested_pw"
  },
  "c":[
    {"c_1":"ccc"},
    {"password":"array_pw"}
  ]}`)

	jsonExpected := []byte(`{
  "a":"aaa",
  "password":"***",
  "b":{
    "b_1":"bbb",
    "password":"***"
  },
  "c":[
    {"c_1":"ccc"},
    {"password":"***"}
  ]}`)

	valueJsonInput := []byte(`{  
  "key_or_value":{  
    "a":"aaa",
    "b":"key_or_value"
    }
  }`)

	valueJsonExpected := []byte(`{
  "key_or_value":{  
    "a":"aaa",
    "b":"***"
    }
  }`)

	invalidJsonInput := []byte(`{
  "key_or_value":{
    a:"aaa",
    "b":"key_or_value"
    },
  }`)

	invalidJsonExpected := []byte(`{
  "***":{
    a:"aaa",
    "b":"***"
    },
  }`)

	tests := []struct {
		name string
		args PiiFilter
		td   data.TraceData
		want []data.TraceData
	}{
		{
			name: "filter_key",
			args: PiiFilter{
				KeyRegExs: []PiiElement{
					{
						Regex:    "^password$",
						Category: "sensitive",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"password": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "abc123"}},
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
									"password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									"password.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "sensitive"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "filter_value",
			args: PiiFilter{
				ValueRegExs: []PiiElement{
					{
						Regex:    "(?:\\d[ -]*?){13,16}",
						Category: "pci",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"cc": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "4111 2222 3333 4444"}},
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
									"cc": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									"cc.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "pci"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "regex_chain",
			args: PiiFilter{
				ValueRegExs: []PiiElement{
					{
						Regex:    "aaa",
						Category: "pci",
					},
					{
						Regex:    "bbb",
						Category: "sensitive",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"cc": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "aaa bbb ccc aaa bbb ccc"}},
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
									"cc": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "*** *** ccc *** *** ccc"}},
									},
									"cc.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "pci,sensitive"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "prefix",
			args: PiiFilter{
				Prefixes: []string{
					"a.",
				},
				KeyRegExs: []PiiElement{
					{
						Regex:    "^password$",
						Category: "sensitive",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"a.password": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "aaa123"}},
								},
								"b.password": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "bbb123"}},
								},
								"password": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "ccc123"}},
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
									"a.password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									"a.password.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "sensitive"}},
									},
									"b.password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "bbb123"}},
									},
									"password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									"password.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "sensitive"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "sha3_redact",
			args: PiiFilter{
				HashValue: true,
				KeyRegExs: []PiiElement{
					{
						Regex: "^password$",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"password": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "abc123"}},
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
									"password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: sha3Abc123}},
									},
									"password.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: ""}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "json_filter",
			args: PiiFilter{
				KeyRegExs: []PiiElement{
					{
						Regex:    "^password$",
						Category: "sensitive",
					},
				},
				ComplexData: []PiiComplexData{
					{
						Key:  "custom.data",
						Type: "json",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"custom.data": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(jsonInput)}},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "value_json_filter",
			args: PiiFilter{
				ValueRegExs: []PiiElement{
					{
						Regex:    "key_or_value",
						Category: "pii",
					},
				},
				ComplexData: []PiiComplexData{
					{
						Key:  "custom.data",
						Type: "json",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"custom.data": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(valueJsonInput)}},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "invalid_json_filter",
			args: PiiFilter{
				ValueRegExs: []PiiElement{
					{
						Regex:    "key_or_value",
						Category: "pii",
					},
				},
				ComplexData: []PiiComplexData{
					{
						Key:  "custom.data",
						Type: "json",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"custom.data": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(invalidJsonInput)}},
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
									"custom.data": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(invalidJsonExpected)}},
									},
									"custom.data.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "pii"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "sql_filter",
			args: PiiFilter{
				ComplexData: []PiiComplexData{
					{
						Key:  "sql.query",
						Type: "sql",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"sql.query": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "select password from user where name = 'dave' or name =\"bob\";"}},
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
									"sql.query": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "select password from user where name = '***' or name =\"***\";"}},
									},
									"sql.query.redacted": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: ""}},
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

			// need to special case the json test, as input/expected json can't
			// be a simple string compare
			if tt.name == "json_filter" {
				gomega.RegisterTestingT(t)
				redacted := tt.td.Spans[0].Attributes.AttributeMap["custom.data"].GetStringValue().Value
				gomega.Expect(jsonExpected).Should(gomega.MatchJSON(redacted))
				categories := tt.td.Spans[0].Attributes.AttributeMap["custom.data.redacted"]
				gomega.Expect(categories).ShouldNot(gomega.BeNil())
				gomega.Expect(categories.GetStringValue().Value).Should(gomega.Equal("sensitive,sensitive,sensitive"))
			} else if tt.name == "value_json_filter" {
				gomega.RegisterTestingT(t)
				redacted := tt.td.Spans[0].Attributes.AttributeMap["custom.data"].GetStringValue().Value
				gomega.Expect(valueJsonExpected).Should(gomega.MatchJSON(redacted))
				categories := tt.td.Spans[0].Attributes.AttributeMap["custom.data.redacted"]
				gomega.Expect(categories).ShouldNot(gomega.BeNil())
				gomega.Expect(categories.GetStringValue().Value).Should(gomega.Equal("pii"))
			} else {
				if diff := cmp.Diff(sinkExporter.AllTraces(), tt.want); diff != "" {
					t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
				}
			}
		})
	}
}
