package piifilterprocessor

import (
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

func (f *jsonFilter) Filter(input string, key string, filterData *FilterData) (bool, bool) {
	f.logger.Debug("Parsing json", zap.String("json", input))

	if len(input) == 0 {
		return false, false
	}

	err := jsoniter.UnmarshalFromString(input, &f.json)
	if err != nil {
		f.logger.Info("Problem parsing json", zap.Error(err), zap.String("json", input))
		return true, false
	}

	filtered, redacted := f.filterJSON(f.json, nil, "", key, jsonPathPrefix, false, filterData)
	f.json = redacted

	return false, filtered
}

func (f *jsonFilter) FilteredText() string {
	if len(f.filteredText) == 0 {
		var err error
		f.filteredText, err = jsoniter.MarshalToString(f.json)
		if err != nil {
			f.logger.Info("Problem converting json", zap.Error(err))
		}
	}

	return f.filteredText
}

func (f *jsonFilter) filterJSON(t interface{}, piiElem *PiiElement, key string, actualKey string, jsonPath string, checked bool, filterData *FilterData) (bool, interface{}) {
	switch tt := t.(type) {
	case []interface{}:
		filtered, redacted := f.filterJSONArray(tt, piiElem, key, actualKey, jsonPath, checked, filterData)
		return filtered, redacted
	case map[string]interface{}:
		filtered, redacted := f.filterJSONMap(tt, piiElem, key, actualKey, jsonPath, checked, filterData)
		return filtered, redacted
	case interface{}:
		filtered, redacted := f.filterJSONScalar(tt, piiElem, key, actualKey, jsonPath, checked, filterData)
		return filtered, redacted
	}

	return false, t
}

func (f *jsonFilter) filterJSONArray(t []interface{}, piiElem *PiiElement, key string, actualKey string, jsonPath string, checked bool, filterData *FilterData) (bool, interface{}) {
	filtered := false
	for i, v := range t {
		matchedPiiElem := piiElem
		tempJsonPath := fmt.Sprintf("%s[%d]", jsonPath, i)
		if matchedPiiElem == nil {
			_, matchedPiiElem = f.pfp.matchKeyRegexs(key, actualKey, tempJsonPath)
		}
		modified, redacted := f.filterJSON(v, matchedPiiElem, key, actualKey, tempJsonPath, true, filterData)
		if modified {
			t[i] = redacted
		}
		filtered = modified || filtered
	}

	return filtered, t
}

func (f *jsonFilter) filterJSONMap(t map[string]interface{}, piiElem *PiiElement, key string, actualKey string, jsonPath string, checked bool, filterData *FilterData) (bool, interface{}) {
	filtered := false
	for k, v := range t {
		var mapJSONPath string
		mapJSONPath = jsonPath + "." + k

		matchedPiiElem := piiElem
		if matchedPiiElem == nil {
			_, matchedPiiElem = f.pfp.matchKeyRegexs(k, actualKey, mapJSONPath)
		}
		modified, redacted := f.filterJSON(v, matchedPiiElem, k, actualKey, mapJSONPath, true, filterData)
		if modified {
			t[k] = redacted
		}
		filtered = modified || filtered
	}

	return filtered, t
}

func (f *jsonFilter) filterJSONScalar(t interface{}, piiElem *PiiElement, key string, actualKey string, jsonPath string, checked bool, filterData *FilterData) (bool, interface{}) {
	if piiElem == nil && !checked {
		_, piiElem = f.pfp.matchKeyRegexs(key, actualKey, jsonPath)
	}

	switch tt := t.(type) {
	case string:
		if piiElem != nil {
			_, redacted := f.pfp.filterMatchedKey(piiElem, key, actualKey, tt, jsonPath, filterData)
			return true, redacted
		}
		vvFiltered, stringValueFiltered := f.pfp.filterStringValueRegexs(tt, actualKey, jsonPath, filterData)
		if stringValueFiltered {
			return true, vvFiltered
		}
	case interface{}:
		if piiElem != nil {
			str := fmt.Sprintf("%v", tt)
			isModified, redacted := f.pfp.filterMatchedKey(piiElem, key, actualKey, str, jsonPath, filterData)
			return isModified, redacted
		}
	}
	return false, t
}
