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
	jsoniter "github.com/json-iterator/go"
	"golang.org/x/crypto/sha3"
)

// PiiFilter identifies configuration for PII filtering
type PiiElement struct {
	Regex    string `mapstructure:"regex"`
	Catagory string `mapstructure:"catagory"`
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
	// HashValue true will has the filtered value
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
	hasFilters   bool
	hashValue    bool
	prefixes     []string
	keyRegexs    map[*regexp.Regexp]string
	valueRegexs  map[*regexp.Regexp]string
	complexData  []PiiComplexData
}

var _ processor.TraceProcessor = (*piifilterprocessor)(nil)

func NewTraceProcessor(nextConsumer consumer.TraceConsumer, filter *PiiFilter) (processor.TraceProcessor, error) {
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

	hasFilters := len(keyRegexs) > 0 || len(valueRegexs) > 0

	return &piifilterprocessor{
		nextConsumer: nextConsumer,
		hasFilters:   hasFilters,
		hashValue:    filter.HashValue,
		prefixes:     prefixes,
		keyRegexs:    keyRegexs,
		valueRegexs:  valueRegexs,
		complexData:  filter.ComplexData,
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
		regexps[regexp] = elem.Catagory
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
			if match, catagory := pfp.matchesKeyRegex(key); match {
				pfp.filterValue(catagory, value)
				continue
			}

			if match, catagory := pfp.matchesValueRegex(value); match {
				pfp.filterValue(catagory, value)
				continue
			}
		}

		// complex data filtering is always matched on entire key, not
		// prefixes, so can look up attribute directly, rather than iterating
		// over all keys looking for a match
		pfp.filterComplexData(span.Attributes.AttributeMap)
	}

	return pfp.nextConsumer.ConsumeTraceData(ctx, td)
}

func (pfp *piifilterprocessor) matchesKeyRegex(key string) (bool, string) {
	truncatedKey := pfp.getTruncatedKey(key)

	for regexp, catagory := range pfp.keyRegexs {
		if regexp.MatchString(truncatedKey) {
			return true, catagory
		}
	}

	return false, ""
}

func (pfp *piifilterprocessor) matchesValueRegex(value *tracepb.AttributeValue) (bool, string) {
	valueString := value.GetStringValue().Value

	for regexp, catagory := range pfp.valueRegexs {
		if regexp.MatchString(valueString) {
			return true, catagory
		}
	}

	return false, ""
}

func (pfp *piifilterprocessor) filterComplexData(attribMap map[string]*tracepb.AttributeValue) {
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
				continue
			}

			switch dataType {
			case "json":
				pfp.filterJson(attrib)
				break
			default: // ignore all other types
				break
			}
		}
	}
}

func (pfp *piifilterprocessor) filterJson(value *tracepb.AttributeValue) {
	var f interface{}
	jsonString := value.GetStringValue().Value
	// strip any leading/trailing quates which may have been added to the value
	jsonString = strings.TrimPrefix(jsonString, "\"")
	jsonString = strings.TrimSuffix(jsonString, "\"")
	jsoniter.UnmarshalFromString(jsonString, &f)

	filteredCatagories := list.New()
	var traverseJson func(map[string]interface{})
	traverseJson = func(x map[string]interface{}) {
		for k, v := range x {
			switch vv := v.(type) {
			case string:
				if match, catagory := pfp.matchesKeyRegex(k); match {
					x[k] = pfp.filterStringValue(vv)
					filteredCatagories.PushBack(catagory)
				}
			case map[string]interface{}:
				traverseJson(vv)
			case []interface{}:
				for _, u := range vv {
					traverseJson(u.(map[string]interface{}))
				}
			}
		}
	}
	traverseJson(f.(map[string]interface{}))

	//TODO: add attribute to annotate filtered state, along with catagory
	if filteredCatagories.Len() > 0 {
		filteredJson, _ := jsoniter.MarshalToString(f)
		value.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: filteredJson}}
	}
}

func (pfp *piifilterprocessor) filterValue(catagory string, value *tracepb.AttributeValue) {
	filteredValue := pfp.filterStringValue(value.GetStringValue().Value)

	//TODO: add attribute to annotate filtered state, along with catagory
	value.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: filteredValue}}
}

func (pfp *piifilterprocessor) filterStringValue(value string) string {
	var filtered string
	if pfp.hashValue {
		h := make([]byte, 64)
		sha3.ShakeSum256(h, []byte(value))
		filtered = fmt.Sprintf("%x", h)
	} else {
		filtered = "***"
	}

	return filtered
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
