//+build collector_modsec

package piifilterprocessor

import (
	"context"
	"strings"
	"testing"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/inspector"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_piifilterprocessor_modsec_ConsumeTraceData(t *testing.T) {
	tests := []struct {
		name string
		args PiiFilter
		td   data.TraceData
		want []data.TraceData
	}{
		{
			name: "modsecanomaly",
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
				Modsec: inspector.ModsecConfig{
					Rules: `SecRule REQUEST_HEADERS:password "attacker" "id:20"`,
				},
			},
			td: data.TraceData{
				Spans: []*tracepb.Span{
					{
						Name: &tracepb.TruncatableString{Value: "test"},
						Attributes: &tracepb.Span_Attributes{
							AttributeMap: map[string]*tracepb.AttributeValue{
								"http.request.header.password": {
									Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "attacker"}},
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
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "Gh8KCHBhc3N3b3JkEhMKERIPCgcKAyoqKhADEAUYCCIASggKBgoCMjAgAQ=="}},
									},
									dlpTag: {
										Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "[{\"key\":\"http.request.header.password\",\"path\":\"\",\"type\":\"sensitive\"}]"}},
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
