package piifilterprocessor

import (
	"container/list"
	"net/url"

	"go.uber.org/zap"
)

type urlEncodedFilter struct {
	pfp          *piifilterprocessor
	logger       *zap.Logger
	filteredText string
}

func newURLEncodedFilter(pfp *piifilterprocessor, logger *zap.Logger) *urlEncodedFilter {
	return &urlEncodedFilter{
		pfp:    pfp,
		logger: logger,
	}
}

func (f *urlEncodedFilter) Filter(input string, key string, dlpElements *list.List) (bool, bool) {
	f.logger.Debug("Parsing url encoded data", zap.String("urlEncoded", input))

	if len(input) == 0 {
		return false, false
	}

	params, err := url.ParseQuery(input)
	if err != nil {
		f.logger.Info("Problem parsing json", zap.Error(err), zap.String("urlEncoded", input))
		return true, false
	}

	v := url.Values{}
	var filtered bool
	for param, values := range params {
		for _, value := range values {
			matchedKey, redacted := f.pfp.filterKeyRegexs(param, param, value, "", dlpElements)
			if matchedKey {
				v.Add(param, redacted)
				filtered = true
			} else {
				redacted, stringValueFiltered := f.pfp.filterStringValueRegexs(value, param, "", dlpElements)
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
		f.filteredText = v.Encode()
	} else {
		f.filteredText = input
	}

	return false, filtered
}

func (f *urlEncodedFilter) FilteredText() string {
	return f.filteredText
}
