package piifilterprocessor

import (
	"net/http"
	"strings"

	"go.uber.org/zap"
)

type cookieFilter struct {
	pfp          *piifilterprocessor
	logger       *zap.Logger
	filteredText string
}

func newCookieFilter(pfp *piifilterprocessor, logger *zap.Logger) *cookieFilter {
	return &cookieFilter{
		pfp:    pfp,
		logger: logger,
	}
}

func mapKeyToHeader(key string) string {
	switch key {
	case "http.request.header.cookie":
		return "Cookie"
	case "http.response.header.set-cookie":
		return "Set-Cookie"
	}
	return ""
}

func parseCookies(key string, value string) []*http.Cookie {
	switch key {
	case "http.request.header.cookie":
		header := http.Header{}
		header.Add("Cookie", value)
		request := http.Request{Header: header}
		return request.Cookies()

	case "http.response.header.set-cookie":
		header := http.Header{}
		header.Add("Set-Cookie", value)
		response := http.Response{Header: header}
		return response.Cookies()
	}
	return nil
}

func stitchCookies(cookies []*http.Cookie) string {
	length := len(cookies)
	cookieStrSlice := make([]string, length)
	for idx, cookie := range cookies {
		cookieStrSlice[idx] = cookie.String()
	}
	return strings.Join(cookieStrSlice, "; ")
}

func (f *cookieFilter) Filter(input, key string, filterData *FilterData) (bool, bool) {
	f.logger.Debug("Parsing cookie encoded data", zap.String("cookie", input))

	if len(input) == 0 {
		return false, false
	}

	cookies := parseCookies(key, input)
	if cookies == nil {
		return true, false
	}
	filtered := false
	for _, cookie := range cookies {
		matchedKey, redacted := f.pfp.filterKeyRegexs(cookie.Name, key, cookie.Value, cookie.Name, filterData)
		if matchedKey {
			cookie.Value = redacted
			filtered = true
		} else {
			redacted, stringValueFiltered := f.pfp.filterStringValueRegexs(cookie.Value, key, cookie.Name, filterData)
			if stringValueFiltered {
				filtered = true
				cookie.Value = redacted
			}
		}
	}

	if filtered {
		f.filteredText = stitchCookies(cookies)
	}

	return false, filtered
}

func (f *cookieFilter) FilteredText() string {
	return f.filteredText
}
