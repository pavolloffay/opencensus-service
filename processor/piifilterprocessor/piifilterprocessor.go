package piifilterprocessor

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
)

const (
	redactedText = "***"
)

// PiiFilter identifies configuration for PII filtering
type PiiElement struct {
	Regex    string `mapstructure:"regex"`
	Category string `mapstructure:"category"`
}

// ComplexData identifes the attribute names which define
// where the content is and where the content type or
// the type itself
type PiiComplexData struct {
	Key     string `mapstructure:"key"`
	Type    string `mapstructure:"type"`
	TypeKey string `mapstructure:"type-key"`
}

type PiiFilter struct {
	// HashValue when true will sha3 the filtered value
	HashValue bool `mapstructure:"hash-value"`
	// Prefixes attribute name prefix to match the keyword against
	Prefixes []string `mapstructure:"prefixes"`
	// // Keywords are the attribute name of which the value will be filtered
	// Keywords []string `mapstructure:"keywords"`
	// Regexs are the attribute name of which the value will be filtered
	// when the regex matches the name
	KeyRegExs []PiiElement `mapstructure:"key-regexs"`
	// Regexs are the attribute value which will be filtered when
	// the regex matches
	ValueRegExs []PiiElement `mapstructure:"value-regexs"`
	// ComplexData contains all complex data types to filter, such
	// as json, sql etc
	ComplexData []PiiComplexData `mapstructure:"complex-data"`
}

type piifilterprocessor struct {
	nextConsumer consumer.TraceConsumer
	logger       *zap.Logger
	hasFilters   bool
	hashValue    bool
	prefixes     []string
	keyRegexs    map[*regexp.Regexp]string
	valueRegexs  map[*regexp.Regexp]string
	complexData  map[string]PiiComplexData
}

var _ processor.TraceProcessor = (*piifilterprocessor)(nil)

func NewTraceProcessor(nextConsumer consumer.TraceConsumer, filter *PiiFilter, logger *zap.Logger) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, errors.New("nextConsumer is nil")
	}

	lenPrefixes := len(filter.Prefixes)
	prefixes := make([]string, lenPrefixes)
	if lenPrefixes > 0 {
		seenPrefixes := make(map[string]bool)
		for i, prefix := range filter.Prefixes {
			if seenPrefixes[prefix] {
				return nil, fmt.Errorf("prefix %s already specified", prefix)
			}
			seenPrefixes[prefix] = true

			prefixes[i] = prefix
		}
	}

	keyRegexs, err := compileRegexs(filter.KeyRegExs)
	if err != nil {
		return nil, err
	}

	valueRegexs, err := compileRegexs(filter.ValueRegExs)
	if err != nil {
		return nil, err
	}

	complexData := make(map[string]PiiComplexData)
	for _, elem := range filter.ComplexData {
		complexData[elem.Key] = elem
	}

	hasFilters := len(keyRegexs) > 0 || len(valueRegexs) > 0 || len(complexData) > 0

	return &piifilterprocessor{
		nextConsumer: nextConsumer,
		logger:       logger,
		hasFilters:   hasFilters,
		hashValue:    filter.HashValue,
		prefixes:     prefixes,
		keyRegexs:    keyRegexs,
		valueRegexs:  valueRegexs,
		complexData:  complexData,
	}, nil
}

func compileRegexs(regexs []PiiElement) (map[*regexp.Regexp]string, error) {
	lenRegexs := len(regexs)
	regexps := make(map[*regexp.Regexp]string, lenRegexs)
	for _, elem := range regexs {
		regexp, err := regexp.Compile(elem.Regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling key regex %s already specified", elem.Regex)
		}
		regexps[regexp] = elem.Category
	}

	return regexps, nil
}

func (pfp *piifilterprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	if !pfp.hasFilters {
		return pfp.nextConsumer.ConsumeTraceData(ctx, td)
	}

	for _, span := range td.Spans {
		if span == nil || span.Attributes == nil || len(span.Attributes.AttributeMap) == 0 {
			continue
		}

		for key, value := range span.Attributes.AttributeMap {
			if _, ok := pfp.complexData[key]; ok {
				// value filters on complex data are run as part of
				// complex data filtering
				continue
			} else if pfp.filterKeyRegexs(span, key, value) {
				// the key regex filters the entire value, so no
				// need to run the value filter
				continue
			}

			pfp.filterValueRegexs(span, key, value)
		}

		// complex data filtering is always matched on entire key, not
		// prefixes, so can look up attribute directly, rather than iterating
		// over all keys looking for a match
		pfp.filterComplexData(span)
	}

	return pfp.nextConsumer.ConsumeTraceData(ctx, td)
}

func (pfp *piifilterprocessor) filterKeyRegexs(span *tracepb.Span, key string, value *tracepb.AttributeValue) bool {
	truncatedKey := pfp.getTruncatedKey(key)

	for regexp, category := range pfp.keyRegexs {
		if regexp.MatchString(truncatedKey) {
			redacted := pfp.redactString(value.GetStringValue().Value)
			filteredCategories := list.New()
			filteredCategories.PushBack(category)
			pfp.replaceValue(span, filteredCategories, key, value, redacted)
			return true
		}
	}

	return false
}

func (pfp *piifilterprocessor) filterValueRegexs(span *tracepb.Span, key string, value *tracepb.AttributeValue) {
	valueString := value.GetStringValue().Value

	valueString, filteredCategories := pfp.filterStringValueRegexs(valueString)

	if filteredCategories.Len() > 0 {
		pfp.replaceValue(span, filteredCategories, key, value, valueString)
	}
}

func (pfp *piifilterprocessor) filterStringValueRegexs(value string) (string, *list.List) {
	filteredCategories := list.New()
	for regexp, category := range pfp.valueRegexs {
		var filtered bool
		filtered, value = pfp.replacingRegex(value, regexp)
		if filtered {
			filteredCategories.PushBack(category)
		}
	}

	return value, filteredCategories
}

func (pfp *piifilterprocessor) filterComplexData(span *tracepb.Span) {
	attribMap := span.GetAttributes().AttributeMap
	for _, elem := range pfp.complexData {
		if attrib, ok := attribMap[elem.Key]; ok {
			var dataType string
			if len(elem.Type) > 0 {
				dataType = elem.Type
			} else {
				if typeValue, ok := attribMap[elem.TypeKey]; ok {
					dataType = getDataType(typeValue.GetStringValue().Value)
				}
			}

			// couldn't work out data type, so ignore
			if len(dataType) == 0 {
				pfp.logger.Debug("Unknown data type", zap.String("attribute", elem.TypeKey))
				continue
			}

			switch dataType {
			case "json":
				pfp.filterJson(span, elem.Key, attrib)
				break
			default: // ignore all other types
				pfp.logger.Debug("Not filtering complex data type", zap.String("attribute", elem.TypeKey), zap.String("type", dataType))
				break
			}
		}
	}
}

func (pfp *piifilterprocessor) filterJson(span *tracepb.Span, key string, value *tracepb.AttributeValue) {
	jsonString := value.GetStringValue().Value
	// strip any leading/trailing quates which may have been added to the value
	jsonString = strings.TrimPrefix(jsonString, "\"")
	jsonString = strings.TrimSuffix(jsonString, "\"")

	filter := NewJsonFilter(pfp, pfp.logger)
	parseFail, jsonChanged := filter.Filter(jsonString)

	// if json is invalid, run the value filter on the json string to try and
	// filter out any keywords out of the string
	if parseFail {
		pfp.filterValueRegexs(span, key, value)
	}

	if jsonChanged {
		pfp.replaceValue(span, filter.FilteredCatagofies(), key, value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) replacingRegex(value string, regex *regexp.Regexp) (bool, string) {
	matchCount := 0

	filtered := regex.ReplaceAllStringFunc(value, func(src string) string {
		matchCount++
		return pfp.redactString(src)
	})

	return matchCount > 0, filtered
}

func (pfp *piifilterprocessor) redactString(value string) string {
	if pfp.hashValue {
		h := make([]byte, 64)
		sha3.ShakeSum256(h, []byte(value))
		return fmt.Sprintf("%x", h)
	} else {
		return redactedText
	}
}

func (pfp *piifilterprocessor) replaceValue(span *tracepb.Span, categories *list.List, key string, value *tracepb.AttributeValue, newValue string) {
	value.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: newValue}}

	var concatedCategories strings.Builder
	for elem := categories.Front(); elem != nil; elem = elem.Next() {
		if concatedCategories.Len() > 0 {
			concatedCategories.WriteString(",")
		}
		concatedCategories.WriteString(elem.Value.(string))
	}

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: concatedCategories.String()}}
	span.GetAttributes().AttributeMap[key+".redacted"] = pbAttrib
}

func (pfp *piifilterprocessor) getTruncatedKey(key string) string {
	for i := range pfp.prefixes {
		if strings.HasPrefix(key, pfp.prefixes[i]) {
			return strings.TrimPrefix(key, pfp.prefixes[i])
		}
	}

	return key
}

func getDataType(dataType string) string {
	lcDataType := strings.ToLower(dataType)

	switch lcDataType {
	case "json", "text/json", "application/json": //TODO: should we just search for json substr?
		lcDataType = "json"
	default:
	}

	return lcDataType
}
