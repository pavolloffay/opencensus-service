package piifilterprocessor

import (
	"container/list"
	"testing"

	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/inspector"
	"github.com/onsi/gomega"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_piifilterprocessor_json_EmptyString(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	filter := newJSONFilter(nil, logger)

	err, filtered := filter.Filter("", "attrib_key", nil)
	assert.False(t, err)
	assert.False(t, filtered)
}

func Test_piifilterprocessor_json_StringConversion(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	filter := newJSONFilter(nil, logger)

	input := "bob"
	err, filtered := filter.Filter(input, "attrib_key", nil)
	assert.True(t, err)
	assert.False(t, filtered)
}

func Test_piifilterprocessor_json_OuterArrayFilter(t *testing.T) {
	input := "[{\"a\": \"1\"},{\"password\": \"abc\"}]"
	expected := "[{\"a\": \"1\"},{\"password\": \"***\"}]"
	filterJSON(t, input, expected, false, true)
}

func Test_piifilterprocessor_json_InnerArrayFilter(t *testing.T) {
	input := "{\"a\": [{\"b\": \"1\"}, {\"password\": \"abc\"}]}"
	expected := "{\"a\": [{\"b\": \"1\"}, {\"password\": \"***\"}]}"
	filterJSON(t, input, expected, false, true)
}

func Test_piifilterprocessor_json_ArrayInKeyFilter(t *testing.T) {
	input := "{\"a\": [{\"b\": \"1\"}, {\"password\": [\"12\",\"34\",\"56\"]}]}"
	expected := "{\"a\": [{\"b\": \"1\"}, {\"password\": [\"***\",\"***\",\"***\"]}]}"
	filterJSON(t, input, expected, false, true)
}

func Test_piifilterprocessor_json_ObjectInKeyFilter(t *testing.T) {
	input := "{\"a\": [{\"b\": \"1\"}, {\"password\":{\"key1\":[\"12\",\"34\",\"56\"], \"key2\":\"val\"}}]}"
	expected := "{\"a\": [{\"b\": \"1\"}, {\"password\": {\"key1\":[\"***\",\"***\",\"***\"], \"key2\":\"***\"}}]}"
	filterJSON(t, input, expected, false, true)
}

func Test_piifilterprocessor_json_NonStringScalarFilter(t *testing.T) {
	input := "{\"a\": [{\"b\": \"1\"}, {\"password\":{\"key1\":[12,34.1,true], \"key2\":false}}]}"
	expected := "{\"a\": [{\"b\": \"1\"}, {\"password\": {\"key1\":[\"***\",\"***\",\"***\"], \"key2\":\"***\"}}]}"
	filterJSON(t, input, expected, false, true)
}

func Test_piifilterprocessor_json_SimpleArrayFilter(t *testing.T) {
	input := "[\"12\",\"34\",\"56\"]"
	expected := "[\"12\",\"34\",\"56\"]"
	filterJSON(t, input, expected, false, true)
}

func Test_piifilterprocessor_json_MapFilter(t *testing.T) {
	input := "{\"a\": \"1\",\"password\": \"abc\"}"
	expected := "{\"a\": \"1\",\"password\": \"***\"}"
	filterJSON(t, input, expected, false, true)
}

func filterJSON(t *testing.T, input string, expectedJSON string, expectedErr bool, expectedFiltered bool) {
	gomega.RegisterTestingT(t)

	logger := zap.New(zapcore.NewNopCore())
	config := &PiiFilter{HashValue: false,
		KeyRegExs: []PiiElement{
			{
				Regex:    "^password$",
				Category: "sensitive",
			},
		},
	}
	pfp, _ := NewTraceProcessor(exportertest.NewNopTraceExporter(), config, logger)
	filter := newJSONFilter(pfp.(*piifilterprocessor), logger)

	filterData := &FilterData{
		DlpElements:    list.New(),
		RedactedValues: make(map[string][]*inspector.Value),
	}
	err, filtered := filter.Filter(input, "attrib_key", filterData)
	assert.Equal(t, expectedErr, err)
	assert.True(t, expectedFiltered, filtered)
	gomega.Expect(expectedJSON).Should(gomega.MatchJSON(filter.FilteredText()))
}
