package customeridprocessor

import (
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/data"
)

var testSpans = data.TraceData{
	Spans: []*tracepb.Span{
		{
			Name: &tracepb.TruncatableString{Value: "span1"},
			Attributes: &tracepb.Span_Attributes{
				AttributeMap: map[string]*tracepb.AttributeValue{
					"tag1": {
						Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "abc123"}},
					},
				},
			},
		},
		{
			Name: &tracepb.TruncatableString{Value: "span2"},
			Attributes: &tracepb.Span_Attributes{
				AttributeMap: map[string]*tracepb.AttributeValue{
					"tag2": {
						Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "def456"}},
					},
				},
			},
		},
	},
}

var expectedSpans = []data.TraceData{
	{
		Spans: []*tracepb.Span{
			{
				Name: &tracepb.TruncatableString{Value: "span1"},
				Attributes: &tracepb.Span_Attributes{
					AttributeMap: map[string]*tracepb.AttributeValue{
						"tag1": {
							Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "abc123"}},
						},
						customerIDSpanTagKey: {
							Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "test-customer-id"}},
						},
					},
				},
			},
			{
				Name: &tracepb.TruncatableString{Value: "span2"},
				Attributes: &tracepb.Span_Attributes{
					AttributeMap: map[string]*tracepb.AttributeValue{
						"tag2": {
							Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "def456"}},
						},
						customerIDSpanTagKey: {
							Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "test-customer-id"}},
						},
					},
				},
			},
		},
	},
}

var testSpansNoAttributes = data.TraceData{
	Spans: []*tracepb.Span{
		{
			Name: &tracepb.TruncatableString{Value: "span1"},
		},
		{
			Name: &tracepb.TruncatableString{Value: "span2"},
		},
	},
}

var testSpansNoAttributesMap = data.TraceData{
	Spans: []*tracepb.Span{
		{
			Name:       &tracepb.TruncatableString{Value: "span1"},
			Attributes: &tracepb.Span_Attributes{},
		},
		{
			Name:       &tracepb.TruncatableString{Value: "span2"},
			Attributes: &tracepb.Span_Attributes{},
		},
	},
}

var expectedSpansForNoAttributesSpans = []data.TraceData{
	{
		Spans: []*tracepb.Span{
			{
				Name: &tracepb.TruncatableString{Value: "span1"},
				Attributes: &tracepb.Span_Attributes{
					AttributeMap: map[string]*tracepb.AttributeValue{
						customerIDSpanTagKey: {
							Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "test-customer-id"}},
						},
					},
				},
			},
			{
				Name: &tracepb.TruncatableString{Value: "span2"},
				Attributes: &tracepb.Span_Attributes{
					AttributeMap: map[string]*tracepb.AttributeValue{
						customerIDSpanTagKey: {
							Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "test-customer-id"}},
						},
					},
				},
			},
		},
	},
}
