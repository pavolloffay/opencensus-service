package piifilterprocessor

import (
	"container/list"
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"mime"
	"regexp"
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	proto "github.com/golang/protobuf/proto"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/inspector"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
)

const (
	redactedText  = "***"
	dlpTag        = "traceable.filter.dlp"
	inspectorTag  = "traceable.apidefinition.inspection"
	queryParamTag = "http.request.query.param"
	// In case of empty json path, platform uses strings defined here as path
	requestBodyEmptyJsonPath  = "REQUEST_BODY"
	responseBodyEmptyJsonPath = "RESPONSE_BODY"
)

// PiiFilter identifies configuration for PII filtering
type PiiElement struct {
	Regex    string `mapstructure:"regex"`
	Category string `mapstructure:"category"`
	// Should the value be redacted or not.
	// Default is true and in case it's nil compileRegexes() function in this file
	// will set it to a "true" pointer
	Redact *bool `mapstructure:"redact,omitempty"`
	Fqn    *bool `mapstructure:"fqn,omitempty"`
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
	Key  string `json:"key"`
	Path string `json:"path"` // For complex types such as JSON string
	Type string `json:"type"`
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

type FilterData struct {
	DlpElements             *list.List
	ApiDefinitionInspection *pb.ApiDefinitionInspection
	hasAnomalies            bool
}

type piifilterprocessor struct {
	nextConsumer     consumer.TraceConsumer
	logger           *zap.Logger
	hasFilters       bool
	hashValue        bool
	prefixes         []string
	keyRegexs        map[*regexp.Regexp]PiiElement
	valueRegexs      map[*regexp.Regexp]PiiElement
	complexData      map[string]PiiComplexData
	inspectorManager *inspector.InspectorManager
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

	inspectorManager := inspector.NewInspectorManager(logger)

	return &piifilterprocessor{
		nextConsumer:     nextConsumer,
		logger:           logger,
		hasFilters:       hasFilters,
		hashValue:        filter.HashValue,
		prefixes:         prefixes,
		keyRegexs:        keyRegexs,
		valueRegexs:      valueRegexs,
		complexData:      complexData,
		inspectorManager: inspectorManager,
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
		if elem.Redact == nil {
			redact := true
			elem.Redact = &redact
		}
		if elem.Fqn == nil {
			fqn := false
			elem.Fqn = &fqn
		}
		regexps[regexp] = elem
	}

	return regexps, nil
}

func mapRawToEnriched(rawTag string, path string) (string, string) {
	enrichedTag := rawTag
	enrichedPath := path
	switch rawTag {
	case "http.url":
		enrichedTag = queryParamTag
	case "http.request.body":
		if len(path) == 0 {
			enrichedPath = requestBodyEmptyJsonPath
		}
	case "http.response.body":
		if len(path) == 0 {
			enrichedPath = responseBodyEmptyJsonPath
		}
	}

	return enrichedTag, enrichedPath
}

func (pfp *piifilterprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	if !pfp.hasFilters {
		return pfp.nextConsumer.ConsumeTraceData(ctx, td)
	}

	for _, span := range td.Spans {
		if span == nil || span.Attributes == nil || len(span.Attributes.AttributeMap) == 0 {
			continue
		}

		filterData := &FilterData{
			DlpElements:             list.New(),
			ApiDefinitionInspection: &pb.ApiDefinitionInspection{},
			hasAnomalies:            false,
		}
		for key, value := range span.Attributes.AttributeMap {
			if value.GetStringValue() == nil {
				continue
			}

			if _, ok := pfp.complexData[key]; ok {
				// value filters on complex data are run as part of
				// complex data filtering
				continue
			} else if pfp.filterKeyRegexsAndReplaceValue(span, key, value, filterData) {
				// the key regex filters the entire value, so no
				// need to run the value filter
				continue
			}

			pfp.filterValueRegexs(span, key, value, filterData)
		}

		// complex data filtering is always matched on entire key, not
		// prefixes, so can look up attribute directly, rather than iterating
		// over all keys looking for a match
		pfp.filterComplexData(span, filterData)

		pfp.addDlpAttribute(span, filterData.DlpElements)

		pfp.addInspectorAttribute(span, filterData.hasAnomalies, filterData.ApiDefinitionInspection)
	}

	return pfp.nextConsumer.ConsumeTraceData(ctx, td)
}

func (pfp *piifilterprocessor) filterKeyRegexsAndReplaceValue(span *tracepb.Span, key string, value *tracepb.AttributeValue, filterData *FilterData) bool {
	truncatedKey := pfp.getTruncatedKey(key)

	filtered, redacted := pfp.filterKeyRegexs(truncatedKey, key, value.GetStringValue().Value, "", filterData)
	if filtered {
		pfp.replaceValue(value, redacted)
	}

	return filtered
}

func (pfp *piifilterprocessor) matchKeyRegexs(keyToMatch string, actualKey string, path string) (bool, *PiiElement) {
	for regexp, piiElem := range pfp.keyRegexs {
		if *piiElem.Fqn {
			if regexp.MatchString(path) {
				return true, &piiElem
			}
		} else {
			if regexp.MatchString(keyToMatch) {
				return true, &piiElem
			}
		}

	}
	return false, nil
}

func (pfp *piifilterprocessor) filterMatchedKey(piiElem *PiiElement, keyToMatch string, actualKey string, value string, path string, filterData *FilterData) (bool, string) {
	inspectorKey, enrichedPath := mapRawToEnriched(actualKey, path)

	if len(path) > 0 {
		inspectorKey = fmt.Sprintf("%s.%s", inspectorKey, enrichedPath)
	}

	filterData.hasAnomalies = pfp.inspectorManager.EvaluateInspectors(filterData.ApiDefinitionInspection, inspectorKey, value) || filterData.hasAnomalies

	var redacted string
	if *piiElem.Redact {
		redacted = pfp.redactString(value)
	} else {
		// Dont redact. Just use the same value.
		redacted = value
	}
	// TODO: Move actual key to enriched key when restructuring dlp.
	pfp.addDlpElementToList(filterData.DlpElements, actualKey, path, piiElem.Category)
	return true, redacted
}

func (pfp *piifilterprocessor) filterKeyRegexs(keyToMatch string, actualKey string, value string, path string, filterData *FilterData) (bool, string) {
	for regexp, piiElem := range pfp.keyRegexs {
		if regexp.MatchString(keyToMatch) {
			return pfp.filterMatchedKey(&piiElem, keyToMatch, actualKey, value, path, filterData)
		}
	}

	return false, ""
}

func (pfp *piifilterprocessor) filterValueRegexs(span *tracepb.Span, key string, value *tracepb.AttributeValue, filterData *FilterData) {
	valueString := value.GetStringValue().Value

	valueString, filtered := pfp.filterStringValueRegexs(valueString, key, "", filterData)

	if filtered {
		pfp.replaceValue(value, valueString)
	}
}

func (pfp *piifilterprocessor) filterStringValueRegexs(value string, key string, path string, filterData *FilterData) (string, bool) {
	filtered := false
	for regexp, piiElem := range pfp.valueRegexs {
		filtered, value = pfp.replacingRegex(value, regexp, piiElem)
		if filtered {
			pfp.addDlpElementToList(filterData.DlpElements, key, path, piiElem.Category)
		}
	}

	return value, filtered
}

func (pfp *piifilterprocessor) filterComplexData(span *tracepb.Span, filterData *FilterData) {
	attribMap := span.GetAttributes().AttributeMap
	for _, elem := range pfp.complexData {
		if attrib, ok := attribMap[elem.Key]; ok {
			var dataType string
			if len(elem.Type) > 0 {
				dataType = elem.Type
			} else {
				if typeValue, ok := attribMap[elem.TypeKey]; ok {
					dataType = pfp.getDataType(typeValue.GetStringValue().Value)
				}
			}

			// couldn't work out data type, so ignore
			if len(dataType) == 0 {
				pfp.logger.Debug("Unknown data type", zap.String("attribute", elem.TypeKey))
				continue
			}

			switch dataType {
			case "json":
				pfp.filterJson(span, elem.Key, attrib, filterData)
				break
			case "urlencoded":
				pfp.filterUrlEncoded(span, elem.Key, attrib, filterData)
				break
			case "sql":
				pfp.filterSql(span, elem.Key, attrib, filterData)
				break
			default: // ignore all other types
				pfp.logger.Debug("Not filtering complex data type", zap.String("attribute", elem.TypeKey), zap.String("type", dataType))
				break
			}
		}
	}
}

func (pfp *piifilterprocessor) filterJson(span *tracepb.Span, key string, value *tracepb.AttributeValue, filterData *FilterData) {
	jsonString := value.GetStringValue().Value
	// strip any leading/trailing quotes which may have been added to the value
	jsonString = strings.TrimPrefix(jsonString, "\"")
	jsonString = strings.TrimSuffix(jsonString, "\"")

	filter := newJSONFilter(pfp, pfp.logger)
	parseFail, jsonChanged := filter.Filter(jsonString, key, filterData)

	// if json is invalid, run the value filter on the json string to try and
	// filter out any keywords out of the string
	if parseFail {
		pfp.logger.Info("Problem parsing json. Falling back to value regex filtering", zap.String("json", jsonString))
		pfp.filterValueRegexs(span, key, value, filterData)
	}

	if jsonChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) filterUrlEncoded(span *tracepb.Span, key string, value *tracepb.AttributeValue, filterData *FilterData) {
	urlEncodedString := value.GetStringValue().Value

	filter := newURLEncodedFilter(pfp, pfp.logger)
	parseFail, urlEncodedChanged := filter.Filter(urlEncodedString, key, filterData)

	if parseFail {
		pfp.logger.Info("Problem parsing form url encoded data. Falling back to value regex filtering", zap.String("urlEncoded", urlEncodedString))
		pfp.filterValueRegexs(span, key, value, filterData)
	}

	if urlEncodedChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) filterSql(span *tracepb.Span, key string, value *tracepb.AttributeValue, filterData *FilterData) {
	sqlString := value.GetStringValue().Value

	filter := NewSqlFilter(pfp, pfp.logger)
	parseFail, sqlChanged := filter.Filter(sqlString, key, filterData)

	// if sql is invalid, run the value filter on the sql string to try and
	// filter out any keywords out of the string
	if parseFail {
		pfp.logger.Info("Problem parsing sql. Falling back to value regex filtering", zap.String("sql", sqlString))
		pfp.filterValueRegexs(span, key, value, filterData)
	}

	if sqlChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) replacingRegex(value string, regex *regexp.Regexp, piiElem PiiElement) (bool, string) {
	matchCount := 0

	filtered := regex.ReplaceAllStringFunc(value, func(src string) string {
		matchCount++
		if *piiElem.Redact {
			return pfp.redactString(src)
		} else {
			return src
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

func (pfp *piifilterprocessor) getDataType(dataType string) string {
	mt, _, err := mime.ParseMediaType(dataType)
	if err != nil {
		pfp.logger.Info("Could not parse media type", zap.Error(err), zap.String("dataType", dataType))
		return ""
	}

	lcDataType := mt
	switch lcDataType {
	case "json", "text/json", "text/x-json", "application/json":
		lcDataType = "json"
	case "application/x-www-form-urlencoded":
		lcDataType = "urlencoded"
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
		Key:  key,
		Path: path,
		Type: category,
	}
}

func (pfp *piifilterprocessor) addDlpAttribute(span *tracepb.Span, dlpElements *list.List) {
	if dlpElements.Len() == 0 {
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

	pfp.logger.Debug("DLP tag value", zap.String(dlpTag, dlpAttrVal))

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: dlpAttrVal}}
	span.GetAttributes().AttributeMap[dlpTag] = pbAttrib
}

func (pfp *piifilterprocessor) addInspectorAttribute(span *tracepb.Span, hasAnomalies bool, apiDefinitionInspection *pb.ApiDefinitionInspection) {
	if !hasAnomalies {
		return
	}

	serialized, err := proto.Marshal(apiDefinitionInspection)
	if err != nil {
		pfp.logger.Warn("Problem marshalling Inspector attr object.", zap.Error(err))
		return
	}
	encoded := b64.StdEncoding.EncodeToString(serialized)

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encoded}}
	span.GetAttributes().AttributeMap[inspectorTag] = pbAttrib
}
