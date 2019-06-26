package piifilterprocessor

import (
	"fmt"
	"container/list"

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

func NewJsonFilter(pfp *piifilterprocessor, logger *zap.Logger) *jsonFilter {
	return &jsonFilter{
		pfp:        pfp,
		logger:     logger,
	}
}

func (f *jsonFilter) Filter(input string, key string, dlpElements *list.List) (bool, bool) {
	err := jsoniter.UnmarshalFromString(input, &f.json)
	if err != nil {
		f.logger.Debug("Problem parsing json", zap.Error(err), zap.String("json", input))
		return true, false
	}

	filtered := f.filterJson(f.json.(map[string]interface{}), key, jsonPathPrefix, dlpElements)

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

func (f *jsonFilter) filterJson(t map[string]interface{}, key string, jsonPath string, dlpElements *list.List) bool {
	filtered := false
	for k, v := range t {
		kJsonPath := jsonPath + "." + k

		switch vv := v.(type) {
		case string:
			matchedKey, redacted := f.pfp.filterKeyRegexs(k, key, vv, kJsonPath, dlpElements)
			if matchedKey {
				t[k] = redacted
				filtered = true
			}
			if !matchedKey {
				vvFiltered, stringValueFiltered := f.pfp.filterStringValueRegexs(vv, key, kJsonPath, dlpElements)
				if stringValueFiltered {
					t[k] = vvFiltered
					filtered = true
				}
			}
		case map[string]interface{}:
			filtered = f.filterJson(vv, key, kJsonPath, dlpElements)
		case []interface{}:
			filteredInArray := false
			for i, u := range vv {
				arrJsonPath := fmt.Sprintf("%s[%d]", kJsonPath, i)
				filteredInArray = f.filterJson(u.(map[string]interface{}), key, arrJsonPath, dlpElements)
				if filteredInArray {
					filtered = true
				}
			}
		}
	}
	return filtered
}
