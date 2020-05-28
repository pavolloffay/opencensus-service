package piifilterprocessor

import (
	"context"
	"encoding/json"
	"fmt"
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

func Test_piifilterprocessor_ConsumeTraceData(t *testing.T) {
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

	jsonInputExpectedDlp := "[{\"key\":\"http.request.body\",\"path\":\"password\",\"type\":\"sensitive\"}," +
		"{\"key\":\"http.request.body\",\"path\":\"b.password\",\"type\":\"sensitive\"}," +
		"{\"key\":\"http.request.body\",\"path\":\"c.password\",\"type\":\"sensitive\"}]"

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

	valueJsonInputExpectedDlp := "[{\"key\":\"http.request.body\",\"path\":\"key_or_value.b\",\"type\":\"pii\"}]"

	multipleAttrsExpectedDlpAttrValue := "[{\"key\":\"auth-key\",\"path\":\"\",\"type\":\"authinfo\"}," +
		"{\"key\":\"http.request.body\",\"path\":\"password\",\"type\":\"sensitive\"}," +
		"{\"key\":\"http.request.body\",\"path\":\"b.password\",\"type\":\"sensitive\"}," +
		"{\"key\":\"http.request.body\",\"path\":\"c.password\",\"type\":\"sensitive\"}]"

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
			name: "no_dlp_filtered",
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
								"tag1": {
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
									"tag1": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "abc123"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "filter_key",
			args: PiiFilter{
				Prefixes: []string{"http.request.header."},
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
								"http.request.header.password": {
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
									"http.request.header.password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "GhoKCHBhc3N3b3JkEg4KDBIKCgIQAxAFGAYiAA=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"Key\":\"http.request.header.password\",\"path\":\"\",\"type\":\"sensitive\"}]"}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "filter_key_int_value",
			args: PiiFilter{
				Prefixes: []string{"http.request.header."},
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
								"code": {
									Value: &tracepb.AttributeValue_IntValue{IntValue: 120},
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
									"code": {
										Value: &tracepb.AttributeValue_IntValue{IntValue: 120},
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
								"http.request.body": {
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
									"http.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "Ih4KDFJFUVVFU1RfQk9EWRIOCgwSCgoCEAMQBRgTIgA="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"http.request.body\",\"path\":\"\",\"type\":\"pci\"}]"}},
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
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: ""}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"cc\",\"path\":\"\",\"type\":\"pci\"},{\"key\":\"cc\",\"path\":\"\",\"type\":\"sensitive\"}]"}},
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
					"http.request.header.",
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
								"http.request.header.password": {
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
									"http.request.header.password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									"b.password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "bbb123"}},
									},
									"password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "GhoKCHBhc3N3b3JkEg4KDBIKCgIQAxAFGAYiAA=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"http.request.header.password\",\"path\":\"\",\"type\":\"sensitive\"},{\"key\":\"password\",\"path\":\"\",\"type\":\"sensitive\"}]"}},
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
				RedactStrategy: "Hash",
				Prefixes: []string{
					"http.request.header.",
				},
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
								"http.request.header.password": {
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
									"http.request.header.password": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "GqEBCghwYXNzd29yZBKUAQqRARKOAQqFAQqAATJiYTBiNDdlMzM3MWFiZmNjYjI5ODczYzlhNDVmOTM4MzE2YWZjMDJjNjQ0ZWY5ZTk4NDc4ODkzZjFmNWUzYTczOWZmMDA2ZmE4NWQ4NDE4OTQ5ZWUyZDVlZjQzYjY0ZGY3Y2M5ZmU4YjdjYTcxZmYxZWM2YzFlZDFmNmNmMzdlEAIQBRgGIgA="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"http.request.header.password\",\"path\":\"\",\"type\":\"\"}]"}},
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
						Key:     "http.request.body",
						TypeKey: "http.request.headers.content-type",
					},
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"http.request.body": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(jsonInput)}},
								},
								"http.request.headers.content-type": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string("application/json;charset=utf-8")}},
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
									"http.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(jsonExpected)}},
									},
									"http.request.headers.content-type": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string("application/json;charset=utf-8")}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "Eh0KCmIucGFzc3dvcmQSDwoNGgsKBwoDKioqEAIQBRIdCgpjLnBhc3N3b3JkEg8KDRoLCgcKAyoqKhACEAUSGwoIcGFzc3dvcmQSDwoNGgsKBwoDKioqEAIQBQ=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: jsonInputExpectedDlp}},
									},
								},
							},
						},
					},
				},
			},
		},

		{
			name: "multiple_attributes",
			args: PiiFilter{
				KeyRegExs: []PiiElement{
					{
						Regex:    "^password$",
						Category: "sensitive",
					},
					{
						Regex:    "^auth-key$",
						Category: "authinfo",
					},
				},
				ComplexData: []PiiComplexData{
					{
						Key:  "http.request.body",
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
								"http.request.body": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(jsonInput)}},
								},
								"auth-key": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "some-auth-key"}},
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
									"http.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(jsonExpected)}},
									},
									"auth-key": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "***"}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "EhsKCHBhc3N3b3JkEg8KDRoLCgcKAyoqKhACEAUSHQoKYi5wYXNzd29yZBIPCg0aCwoHCgMqKioQAhAFEh0KCmMucGFzc3dvcmQSDwoNGgsKBwoDKioqEAIQBQ=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: multipleAttrsExpectedDlpAttrValue}},
									},
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
						Key:  "http.request.body",
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
								"http.request.body": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(valueJsonInput)}},
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
									"http.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(valueJsonExpected)}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "IiAKDmtleV9vcl92YWx1ZS5iEg4KDBIKCgIQAxAFGAwiAA=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: valueJsonInputExpectedDlp}},
									},
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
						Key:  "http.request.body",
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
								"http.request.body": {
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
									"http.request.body": {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: string(invalidJsonExpected)}},
									},
									inspectorTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "IiwKDFJFUVVFU1RfQk9EWRIcCgwSCgoCEAMQBRgMIgAKDBIKCgIQAxAFGAwiAA=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"http.request.body\",\"path\":\"\",\"type\":\"pii\"}]"}},
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
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"sql.query\",\"path\":\"\",\"type\":\"sql_filter\"}]"}},
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

				if tt.name == "json_filter" || tt.name == "json_filter_dont_redact" || tt.name == "multiple_attributes" {
					if strings.Contains(s2.Value, "==") {
						return true
					}
				}

				// Strings are JSON objects
				if tt.name != "invalid_json_filter" && strings.HasPrefix(s1.Value, "{") && strings.HasPrefix(s2.Value, "{") {
					return gomega.Expect(s1.Value).Should(gomega.MatchJSON(s2.Value))
				}
				// Strings are JSON arrays
				if strings.HasPrefix(s1.Value, "[{") && strings.HasPrefix(s2.Value, "[{") {
					return compareJsonArrays(s1.Value, s2.Value)
				}

				return cmp.Equal(s1, s2)
			})

			if diff := cmp.Diff(sinkExporter.AllTraces(), tt.want, attributeStringValueCmpOpt); diff != "" {
				t.Errorf("Mismatched TraceData\n-Got +Want:\n\t%s", diff)
			}
		})
	}
}

func compareJsonArrays(expected string, actual string) bool {
	// We are assuming that the tests will have no more than 10 elements
	// Please change this if you want to test using more elements.
	expectedArr := make([]*DlpElement, 10)
	actualArr := make([]*DlpElement, 10)
	err1 := json.Unmarshal([]byte(expected), &expectedArr)
	err2 := json.Unmarshal([]byte(actual), &actualArr)

	if err1 != nil {
		fmt.Printf("Error while unmarshalling expected: %s\n", err1)
		return false
	}

	if err2 != nil {
		fmt.Printf("Error while unmarshalling actual: %s\n", err2)
		return false
	}

	if len(actualArr) != len(expectedArr) {
		return false
	}

	for _, expectedElem := range expectedArr {
		found := false
		for _, actualElem := range actualArr {
			if cmp.Equal(actualElem, expectedElem) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func Test_piifilterprocessor_CompileRegexes(t *testing.T) {
	gomega.RegisterTestingT(t)

	keyRegexes := []PiiElement{
		{
			Regex:    "^a$",
			Category: "sensitive",
		},
		{
			Regex:          "^b$",
			Category:       "sensitive",
			RedactStrategy: "Redact",
		},
		{
			Regex:          "^c$",
			Category:       "sensitive",
			RedactStrategy: "Hash",
		},
	}

	compiledRegexes, err := compileRegexs(keyRegexes, Redact)

	gomega.Expect(err).Should(gomega.BeNil())
	for regex, piiElem := range compiledRegexes {
		if regex.String() == "^a$" || regex.String() == "^b$" {
			gomega.Expect(piiElem.Redact == Redact).Should(gomega.BeTrue(), fmt.Sprintf("For %s: Expected %v. Got %v", regex.String(), Redact, Hash))
		} else {
			gomega.Expect(piiElem.Redact == Hash).Should(gomega.BeTrue(), fmt.Sprintf("For %s: Expected %v. Got %v", regex.String(), Hash, Redact))
		}
	}
}
