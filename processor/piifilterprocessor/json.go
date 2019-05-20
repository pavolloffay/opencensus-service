package piifilterprocessor

import (
	"container/list"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

type jsonFilter struct {
	pfp          *piifilterprocessor
	logger       *zap.Logger
	json         interface{}
	filteredText string
	categories   *list.List
}

func NewJsonFilter(pfp *piifilterprocessor, logger *zap.Logger) *jsonFilter {
	return &jsonFilter{
		pfp:        pfp,
		logger:     logger,
		categories: list.New(),
	}
}

func (f *jsonFilter) Filter(input string) (bool, bool) {
	err := jsoniter.UnmarshalFromString(input, &f.json)
	if err != nil {
		f.logger.Debug("Problem parsing json", zap.Error(err), zap.String("json", input))
		return true, false
	}

	f.filterJson(f.json.(map[string]interface{}))

	return false, f.categories.Len() > 0
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

func (f *jsonFilter) FilteredCatagofies() *list.List {
	return f.categories
}

func (f *jsonFilter) filterJson(t map[string]interface{}) {
	for k, v := range t {
		switch vv := v.(type) {
		case string:
			var matchedKey bool
			for regexp, category := range f.pfp.keyRegexs {
				if regexp.MatchString(k) {
					t[k] = f.pfp.redactString(vv)
					f.categories.PushBack(category)
					matchedKey = true
				}
			}
			if !matchedKey {
				vvFiltered, filteredCategories := f.pfp.filterStringValueRegexs(vv)
				if filteredCategories.Len() > 0 {
					t[k] = vvFiltered
					f.categories.PushFrontList(filteredCategories)
				}
			}
		case map[string]interface{}:
			f.filterJson(vv)
		case []interface{}:
			for _, u := range vv {
				f.filterJson(u.(map[string]interface{}))
			}
		}
	}
}
