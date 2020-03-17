package piifilterprocessor

import (
	"container/list"
	"net/url"
	"testing"

	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_piifilterprocessor_urlencoded_FilterKey(t *testing.T) {
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
	filter := newURLEncodedFilter(pfp.(*piifilterprocessor), logger)

	v := url.Values{}
	v.Add("user", "dave")
	v.Add("password", "mypw$")

	dlpElems := list.New()
	isErr, filtered := filter.Filter(v.Encode(), "password", dlpElems)
	assert.False(t, isErr)
	assert.True(t, filtered)

	filteredEncoded := filter.FilteredText()
	filteredParams, err := url.ParseQuery(filteredEncoded)
	assert.Nil(t, err)
	assert.Equal(t, filteredParams.Get("user"), "dave")
	assert.Equal(t, filteredParams.Get("password"), "***")
}

func Test_piifilterprocessor_urlencoded_FilterValue(t *testing.T) {
	gomega.RegisterTestingT(t)

	logger := zap.New(zapcore.NewNopCore())
	config := &PiiFilter{HashValue: false,
		ValueRegExs: []PiiElement{
			{
				Regex:    "^filter_value$",
				Category: "sensitive",
			},
		},
	}
	pfp, _ := NewTraceProcessor(exportertest.NewNopTraceExporter(), config, logger)
	filter := newURLEncodedFilter(pfp.(*piifilterprocessor), logger)

	v := url.Values{}
	v.Add("key1", "filter_value")
	v.Add("key2", "value2")

	dlpElems := list.New()
	isErr, filtered := filter.Filter(v.Encode(), "", dlpElems)
	assert.False(t, isErr)
	assert.True(t, filtered)

	filteredEncoded := filter.FilteredText()
	filteredParams, err := url.ParseQuery(filteredEncoded)
	assert.Nil(t, err)
	assert.Equal(t, filteredParams.Get("key1"), "***")
	assert.Equal(t, filteredParams.Get("key2"), "value2")
}
