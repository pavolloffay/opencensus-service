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
	jsoniter "github.com/json-iterator/go"
)

const (
	redactedText = "***"
	dlpTag = "dlp"
)

// PiiFilter identifies configuration for PII filtering
type PiiElement struct {
	Regex    string `mapstructure:"regex"`
	Category string `mapstructure:"category"`
	DontRedact bool `mapstructure:"dont-redact"` // Should the value be redacted or not. Default is false i.e to redact
}

// ComplexData identifes the attribute names which define
// where the content is and where the content type or
// the type itself
type PiiComplexData struct {
	Key     string `mapstructure:"key"`
	Type    string `mapstructure:"type"`
	TypeKey string `mapstructure:"type-key"`
}

type DlpElement struct {
	Key     string `json:"key"`
	Path    string `json:"path"` // For complex types such as JSON string
	Type    string `json:"type"`
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
	keyRegexs    map[*regexp.Regexp]PiiElement
	valueRegexs  map[*regexp.Regexp]PiiElement
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

func compileRegexs(regexs []PiiElement) (map[*regexp.Regexp]PiiElement, error) {
	lenRegexs := len(regexs)
	regexps := make(map[*regexp.Regexp]PiiElement, lenRegexs)
	for _, elem := range regexs {
		regexp, err := regexp.Compile(elem.Regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling key regex %s already specified", elem.Regex)
		}
		regexps[regexp] = elem
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

		dlpElements := list.New()
		for key, value := range span.Attributes.AttributeMap {
			if _, ok := pfp.complexData[key]; ok {
				// value filters on complex data are run as part of
				// complex data filtering
				continue
			} else if pfp.filterKeyRegexsAndReplaceValue(span, key, value, dlpElements) {
				// the key regex filters the entire value, so no
				// need to run the value filter
				continue
			}

			pfp.filterValueRegexs(span, key, value, dlpElements)
		}

		// complex data filtering is always matched on entire key, not
		// prefixes, so can look up attribute directly, rather than iterating
		// over all keys looking for a match
		pfp.filterComplexData(span, dlpElements)

		pfp.addDlpAttribute(span, dlpElements)
	}

	return pfp.nextConsumer.ConsumeTraceData(ctx, td)
}

func (pfp *piifilterprocessor) filterKeyRegexsAndReplaceValue(span *tracepb.Span, key string, value *tracepb.AttributeValue, dlpElements *list.List) bool {
	truncatedKey := pfp.getTruncatedKey(key)

	filtered, redacted := pfp.filterKeyRegexs(truncatedKey, key, value.GetStringValue().Value, "", dlpElements)
	if filtered {
		pfp.replaceValue(value, redacted)
	}

	return filtered
}

func (pfp *piifilterprocessor) filterKeyRegexs(keyToMatch string, actualKey string, value string, path string, dlpElements *list.List) (bool, string) {
	for regexp, piiElem := range pfp.keyRegexs {
		if regexp.MatchString(keyToMatch) {
			var redacted string
			if piiElem.DontRedact {
				// Dont redact. Just use the same value.
				redacted = value
			} else {
				redacted = pfp.redactString(value)
			}
			pfp.addDlpElementToList(dlpElements, actualKey, path, piiElem.Category)
			return true, redacted
		}
	}

	return false, ""
}

func (pfp *piifilterprocessor) filterValueRegexs(span *tracepb.Span, key string, value *tracepb.AttributeValue, dlpElements *list.List) {
	valueString := value.GetStringValue().Value

	valueString, filtered := pfp.filterStringValueRegexs(valueString, key, "", dlpElements)

	if filtered {
		pfp.replaceValue(value, valueString)
	}
}

func (pfp *piifilterprocessor) filterStringValueRegexs(value string, key string, path string, dlpElements *list.List) (string, bool) {
	filtered := false
	for regexp, piiElem := range pfp.valueRegexs {
		filtered, value = pfp.replacingRegex(value, regexp, piiElem)
		if filtered {
			pfp.addDlpElementToList(dlpElements, key, path, piiElem.Category)
		}
	}

	return value, filtered
}

func (pfp *piifilterprocessor) filterComplexData(span *tracepb.Span, dlpElements *list.List) {
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
				pfp.filterJson(span, elem.Key, attrib, dlpElements)
				break
			case "sql":
				pfp.filterSql(span, elem.Key, attrib, dlpElements)
				break
			default: // ignore all other types
				pfp.logger.Debug("Not filtering complex data type", zap.String("attribute", elem.TypeKey), zap.String("type", dataType))
				break
			}
		}
	}
}

func (pfp *piifilterprocessor) filterJson(span *tracepb.Span, key string, value *tracepb.AttributeValue, dlpElements *list.List) {
	jsonString := value.GetStringValue().Value
	// strip any leading/trailing quotes which may have been added to the value
	jsonString = strings.TrimPrefix(jsonString, "\"")
	jsonString = strings.TrimSuffix(jsonString, "\"")

	filter := NewJsonFilter(pfp, pfp.logger)
	parseFail, jsonChanged := filter.Filter(jsonString, key, dlpElements)

	// if json is invalid, run the value filter on the json string to try and
	// filter out any keywords out of the string
	if parseFail {
		pfp.logger.Debug("Problem parsing json. Falling back to value regex filtering")
		pfp.filterValueRegexs(span, key, value, dlpElements)
	}

	if jsonChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) filterSql(span *tracepb.Span, key string, value *tracepb.AttributeValue, dlpElements *list.List) {
	sqlString := value.GetStringValue().Value

	filter := NewSqlFilter(pfp, pfp.logger)
	parseFail, sqlChanged := filter.Filter(sqlString, key, dlpElements)

	// if sql is invalid, run the value filter on the sql string to try and
	// filter out any keywords out of the string
	if parseFail {
		pfp.logger.Debug("Problem parsing sql. Falling back to value regex filtering")
		pfp.filterValueRegexs(span, key, value, dlpElements)
	}

	if sqlChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) replacingRegex(value string, regex *regexp.Regexp, piiElem PiiElement) (bool, string) {
	matchCount := 0

	filtered := regex.ReplaceAllStringFunc(value, func(src string) string {
		matchCount++
		if piiElem.DontRedact {
			return src
		} else {
			return pfp.redactString(src)
		}
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

func (pfp *piifilterprocessor) replaceValue(value *tracepb.AttributeValue, newValue string) {
	value.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: newValue}}
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
	case "sql":
		lcDataType = "sql"
	default:
	}

	return lcDataType
}

func (pfp *piifilterprocessor) addDlpElementToList(dlpElements *list.List, key string, path string, category string) {
	newElement := createDlpElement(key, path, category)
	dlpElements.PushBack(newElement)
}

func createDlpElement(key string, path string, category string) *DlpElement {
	return &DlpElement{
		Key: key,
		Path: path,
		Type: category,
	}
}

func (pfp *piifilterprocessor) addDlpAttribute(span *tracepb.Span, dlpElements *list.List) {
	if (dlpElements.Len() == 0) {
		return
	}

	dlpElementsArr := make([]*DlpElement, dlpElements.Len())
	i := 0
	for dlpElem := dlpElements.Front(); dlpElem != nil; dlpElem = dlpElem.Next() {
		dlpElementsArr[i] = dlpElem.Value.(*DlpElement)
		i++
	}

	dlpAttrVal, err := jsoniter.MarshalToString(dlpElementsArr)
	if err != nil {
		pfp.logger.Warn("Problem marshalling DLP attr array.", zap.Error(err))
		return
	}

	pfp.logger.Debug("DLP tag value", zap.String("dlp", dlpAttrVal))

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: dlpAttrVal}}
	span.GetAttributes().AttributeMap[dlpTag] = pbAttrib
}
