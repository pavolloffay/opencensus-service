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

func Test_piifilterprocessor_cookie_FilterKey(t *testing.T) {
	key := "http.request.header.cookie"
	cookieStr := "cookie1=value1; password=value2"
	expected := "cookie1=value1; password=***"
	filterCookie(t, key, cookieStr, expected)
}

func Test_piifilterprocessor_cookie_setcookie_FilterKey(t *testing.T) {
	key := "http.response.header.set-cookie"
	cookieStr := "password=value2; SameSite=Strict"
	expected := "password=***; SameSite=Strict"
	filterCookie(t, key, cookieStr, expected)
}

func filterCookie(t *testing.T, key string, cookieStr string, expected string) {
	gomega.RegisterTestingT(t)
	logger := zap.New(zapcore.NewNopCore())
	config := &PiiFilter{Redact: Redact,
		KeyRegExs: []PiiElement{
			{
				Regex:    "^password$",
				Category: "sensitive",
			},
		},
	}

	pfp, _ := NewTraceProcessor(exportertest.NewNopTraceExporter(), config, logger)
	filter := newCookieFilter(pfp.(*piifilterprocessor), logger)

	filterData := &FilterData{
		DlpElements:    list.New(),
		RedactedValues: make(map[string][]*inspector.Value),
	}
	isErr, filtered := filter.Filter(cookieStr, key, filterData)
	assert.False(t, isErr)
	assert.True(t, filtered)
	filteredText := filter.FilteredText()
	assert.Equal(t, filteredText, expected)
}
