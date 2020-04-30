package piifilterprocessor

import (
	"net/url"

	"go.uber.org/zap"
)

type urlEncodedFilter struct {
	pfp          *piifilterprocessor
	logger       *zap.Logger
	filteredText string
}

const urlAttributeStr = "http.url"

func newURLEncodedFilter(pfp *piifilterprocessor, logger *zap.Logger) *urlEncodedFilter {
	return &urlEncodedFilter{
		pfp:    pfp,
		logger: logger,
	}
}

func (f *urlEncodedFilter) Filter(input string, key string, filterData *FilterData) (bool, bool) {
	f.logger.Debug("Parsing url encoded data", zap.String("urlEncoded", input))

	if len(input) == 0 {
		return false, false
	}

	var u *url.URL
	var err error

	rawString := input
	isUrlAttribute := key == urlAttributeStr
	if isUrlAttribute {
		u, err = url.Parse(input)
		if err != nil {
			return false, false
		}
		rawString = u.RawQuery
	}

	params, err := url.ParseQuery(rawString)
	if err != nil {
		f.logger.Info("Problem parsing urlencoded", zap.Error(err), zap.String("urlEncoded", input))
		return true, false
	}

	v := url.Values{}
	var filtered bool
	for param, values := range params {
		for _, value := range values {
			matchedKey, redacted := f.pfp.filterKeyRegexs(param, key, value, param, filterData)
			if matchedKey {
				v.Add(param, redacted)
				filtered = true
			} else {
				redacted, stringValueFiltered := f.pfp.filterStringValueRegexs(value, key, param, filterData)
				if stringValueFiltered {
					filtered = true
					v.Add(param, redacted)
				} else {
					v.Add(param, value)
				}
			}
		}
	}

	if filtered {
		encoded := v.Encode()
		if isUrlAttribute {
			u.RawQuery = encoded
			f.filteredText = u.String()
		} else {
			f.filteredText = encoded
		}

	} else {
		f.filteredText = input
	}

	return false, filtered
}

func (f *urlEncodedFilter) FilteredText() string {
	return f.filteredText
}
