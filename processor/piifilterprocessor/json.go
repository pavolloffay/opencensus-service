package piifilterprocessor

import (
	"container/list"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

type jsonFilter struct {
	pfp          *piifilterprocessor
	logger       *zap.Logger
	json         interface{}
	filteredText string
}

const jsonPathPrefix = "$"

func newJSONFilter(pfp *piifilterprocessor, logger *zap.Logger) *jsonFilter {
	return &jsonFilter{
		pfp:    pfp,
		logger: logger,
	}
}

func (f *jsonFilter) Filter(input string, key string, dlpElements *list.List) (bool, bool) {
	f.logger.Debug("Parsing json", zap.String("json", input))

	if len(input) == 0 {
		return false, false
	}

	err := jsoniter.UnmarshalFromString(input, &f.json)
	if err != nil {
		f.logger.Debug("Problem parsing json", zap.Error(err))
		return true, false
	}

	filtered := f.filterJSON(f.json, key, jsonPathPrefix, dlpElements)

	return false, filtered
}

func (f *jsonFilter) FilteredText() string {
	if len(f.filteredText) == 0 {
		var err error
		f.filteredText, err = jsoniter.MarshalToString(f.json)
		if err != nil {
			f.logger.Debug("Problem converting json", zap.Error(err))
		}
	}

	return f.filteredText
}

func (f *jsonFilter) filterJSON(t interface{}, key string, jsonPath string, dlpElements *list.List) bool {
	filtered := false
	switch tt := t.(type) {
	case []interface{}:
		filtered = f.filterJSONArray(tt, key, jsonPath, dlpElements)
	case map[string]interface{}:
		filtered = f.filterJSONMap(tt, key, jsonPath, dlpElements)
	}

	return filtered
}

func (f *jsonFilter) filterJSONArray(t []interface{}, key string, jsonPath string, dlpElements *list.List) bool {
	filtered := false
	for i, v := range t {
		arrJSONPath := fmt.Sprintf("%s[%d]", jsonPath, i)
		if f.filterJSON(v, key, arrJSONPath, dlpElements) {
			filtered = true
		}
	}

	return filtered
}

func (f *jsonFilter) filterJSONMap(t map[string]interface{}, key string, jsonPath string, dlpElements *list.List) bool {
	filtered := false
	for k, v := range t {
		kJSONPath := jsonPath + "." + k

		switch vv := v.(type) {
		case string:
			matchedKey, redacted := f.pfp.filterKeyRegexs(k, key, vv, kJSONPath, dlpElements)
			if matchedKey {
				t[k] = redacted
				filtered = true
			}
			if !matchedKey {
				vvFiltered, stringValueFiltered := f.pfp.filterStringValueRegexs(vv, key, kJSONPath, dlpElements)
				if stringValueFiltered {
					t[k] = vvFiltered
					filtered = true
				}
			}
		default:
			if f.filterJSON(v, key, kJSONPath, dlpElements) {
				filtered = true
			}
		}
	}

	return filtered
}
