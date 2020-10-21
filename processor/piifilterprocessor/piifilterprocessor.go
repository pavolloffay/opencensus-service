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

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"
	proto "github.com/golang/protobuf/proto"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/common"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/inspector"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
)

const (
	dlpTag            = "traceable.filter.dlp"
	inspectorTag      = "traceable.apidefinition.inspection"
	queryParamTag     = "http.request.query.param"
	requestCookieTag  = "http.request.cookie"
	responseCookieTag = "http.response.cookie"
	sessionIDTag      = "session.id"
	// In case of empty json path, platform uses strings defined here as path
	requestBodyEmptyJsonPath  = "REQUEST_BODY"
	responseBodyEmptyJsonPath = "RESPONSE_BODY"
)

// PiiFilter identifies configuration for PII filtering
type PiiElement struct {
	Regex             string `mapstructure:"regex"`
	Category          string `mapstructure:"category"`
	RedactStrategy    string `mapstructure:"redaction-strategy"`
	Redact            RedactionStrategy
	Fqn               *bool  `mapstructure:"fqn,omitempty"`
	SessionIdentifier bool   `mapstructure:"session-identifier"`
	SessionIndexes    []int  `mapstructure:"session-indexes"`
	SessionSeparator  string `mapstructure:"session-separator"`
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
	// Global redaction strategy. Defaults to Redact
	RedactStrategy string `mapstructure:"redaction-strategy"`
	Redact         RedactionStrategy
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
	// Config for modsec inspector
	Modsec inspector.ModsecConfig `mapstructure:"modsec-config"`
}

type FilterData struct {
	DlpElements    *list.List
	RedactedValues map[string][]*inspector.Value
	SessionID      string
}

type piifilterprocessor struct {
	nextConsumer     consumer.TraceConsumer
	logger           *zap.Logger
	hasFilters       bool
	redact           RedactionStrategy
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

	filter.Redact = toId(filter.RedactStrategy)

	var globalRedactionStrategy RedactionStrategy
	if int(filter.Redact) == 0 {
		globalRedactionStrategy = Redact
	} else {
		globalRedactionStrategy = filter.Redact
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

	keyRegexs, err := compileRegexs(filter.KeyRegExs, globalRedactionStrategy)
	if err != nil {
		return nil, err
	}

	valueRegexs, err := compileRegexs(filter.ValueRegExs, globalRedactionStrategy)
	if err != nil {
		return nil, err
	}

	complexData := make(map[string]PiiComplexData)
	for _, elem := range filter.ComplexData {
		complexData[elem.Key] = elem
	}

	hasFilters := len(keyRegexs) > 0 || len(valueRegexs) > 0 || len(complexData) > 0

	inspectorManager := inspector.NewInspectorManager(logger, filter.Modsec)

	return &piifilterprocessor{
		nextConsumer:     nextConsumer,
		logger:           logger,
		hasFilters:       hasFilters,
		redact:           globalRedactionStrategy,
		prefixes:         prefixes,
		keyRegexs:        keyRegexs,
		valueRegexs:      valueRegexs,
		complexData:      complexData,
		inspectorManager: inspectorManager,
	}, nil
}

func compileRegexs(regexs []PiiElement, globalRedactionStrategy RedactionStrategy) (map[*regexp.Regexp]PiiElement, error) {
	lenRegexs := len(regexs)
	regexps := make(map[*regexp.Regexp]PiiElement, lenRegexs)
	for _, elem := range regexs {
		regexp, err := regexp.Compile(elem.Regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling key regex %s already specified", elem.Regex)
		}

		elem.Redact = toId(elem.RedactStrategy)
		if int(elem.Redact) == 0 {
			elem.Redact = globalRedactionStrategy
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

	unindexedKey := UnindexedKey(rawTag)
	switch unindexedKey {
	case "http.url":
		enrichedTag = queryParamTag
	case "http.request.header.cookie":
		enrichedTag = requestCookieTag
	case "http.response.header.set-cookie":
		enrichedTag = responseCookieTag
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

func getFullyQuallifiedInspectorKey(actualKey string, path string) string {
	inspectorKey, enrichedPath := mapRawToEnriched(actualKey, path)

	if len(enrichedPath) > 0 {
		inspectorKey = fmt.Sprintf("%s.%s", inspectorKey, enrichedPath)
	}

	return inspectorKey
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
			DlpElements:    list.New(),
			RedactedValues: make(map[string][]*inspector.Value),
		}
		for key, value := range span.Attributes.AttributeMap {
			if value.GetStringValue() == nil {
				continue
			}

			unindexedKey := UnindexedKey(key)
			if _, ok := pfp.complexData[unindexedKey]; ok {
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
		// prefixes, so can look up attribute directly, rather than iterating n
		// over all keys looking for a match
		pfp.filterComplexData(span, filterData)

		pfp.addDlpAttribute(span, filterData.DlpElements)

		pfp.addInspectorAttribute(span, filterData.RedactedValues)

		pfp.addSessionAttribute(span, filterData.SessionID)
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
	inspectorKey := getFullyQuallifiedInspectorKey(actualKey, path)

	isModified, redacted := pfp.redactAndFilterData(piiElem.Redact, value, inspectorKey, filterData)

	if piiElem.SessionIdentifier {
		// When using an auth header for tracking sessions, make sure
		// to only hash the token and not the type, as the token can
		// be tracked in more places than just an auth header.
		if actualKey == "http.request.header.authorization" &&
			strings.HasPrefix(strings.ToLower(value), "bearer ") {
			pfp.setSessionID(piiElem, filterData, value[7:])
		} else {
			pfp.setSessionID(piiElem, filterData, value)
		}
	}

	// TODO: Move actual key to enriched key when restructuring dlp.
	pfp.addDlpElementToList(filterData.DlpElements, actualKey, path, piiElem.Category)
	return isModified, redacted
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
	inspectorKey := getFullyQuallifiedInspectorKey(key, path)

	filtered := false
	for regexp, piiElem := range pfp.valueRegexs {
		var origValue = value
		filtered, value = pfp.replacingRegex(value, inspectorKey, regexp, piiElem, filterData)

		if piiElem.SessionIdentifier {
			pfp.setSessionID(&piiElem, filterData, origValue)
		}

		if filtered {
			pfp.addDlpElementToList(filterData.DlpElements, key, path, piiElem.Category)
		}
	}

	return value, filtered
}

func (pfp *piifilterprocessor) filterComplexData(span *tracepb.Span, filterData *FilterData) {
	attribMap := span.GetAttributes().AttributeMap
	for key, attrib := range span.Attributes.AttributeMap {
		if attrib.GetStringValue() == nil {
			continue
		}

		unindexedKey := UnindexedKey(key)
		if elem, ok := pfp.complexData[unindexedKey]; ok {
			var dataType string
			if len(elem.Type) > 0 {
				dataType = elem.Type
			} else {
				if typeValue, ok := attribMap[elem.TypeKey]; ok {
					dataType = pfp.getDataType(typeValue.GetStringValue().Value)
				}
			}

			if attrib == nil || attrib.GetStringValue() == nil {
				pfp.logger.Debug("nil or non string value", zap.String("attribute", elem.TypeKey))
				continue
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
			case "cookie":
				pfp.filterCookie(span, elem.Key, attrib, filterData)
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
		pfp.logger.Debug("Problem parsing json. Falling back to value regex filtering", zap.String("json", jsonString))
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
		pfp.logger.Debug("Problem parsing form url encoded data. Falling back to value regex filtering", zap.String("urlEncoded", urlEncodedString))
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
		pfp.logger.Debug("Problem parsing sql. Falling back to value regex filtering", zap.String("sql", sqlString))
		pfp.filterValueRegexs(span, key, value, filterData)
	}

	if sqlChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) filterCookie(span *tracepb.Span, key string, value *tracepb.AttributeValue, filterData *FilterData) {
	cookieString := value.GetStringValue().Value

	filter := newCookieFilter(pfp, pfp.logger)
	parseFail, cookieChanged := filter.Filter(cookieString, key, filterData)

	// if cookie is invalid, run the value filter on the cookie string to try and
	// filter out any keywords out of the string
	if parseFail {
		pfp.logger.Debug("Problem parsing cookie. Falling back to value regex filtering", zap.String("cookie", cookieString))
		pfp.filterValueRegexs(span, key, value, filterData)
	}

	if cookieChanged {
		pfp.replaceValue(value, filter.FilteredText())
	}
}

func (pfp *piifilterprocessor) replacingRegex(value string, key string, regex *regexp.Regexp, piiElem PiiElement, filterData *FilterData) (bool, string) {
	matchCount := 0

	filtered := regex.ReplaceAllStringFunc(value, func(src string) string {
		matchCount++
		_, str := pfp.redactAndFilterData(piiElem.Redact, src, key, filterData)
		return str
	})

	return matchCount > 0, filtered
}

func (pfp *piifilterprocessor) redactAndFilterData(redact RedactionStrategy, value string, inspectorKey string, filterData *FilterData) (bool, string) {
	var redacted string
	var isRedacted bool
	switch redact {
	case Redact:
		redacted = common.RedactedText
		isRedacted = true
	case Hash:
		redacted = HashValue(value)
		isRedacted = false
	case Raw:
		redacted = value
		isRedacted = false
	default:
		redacted = common.RedactedText
		isRedacted = true
	}

	val := inspector.NewValue(value, redacted, isRedacted)
	filterData.RedactedValues[inspectorKey] = append(filterData.RedactedValues[inspectorKey], val)

	return true, redacted
}

// HashValue will return a hashed value of the entered string
func HashValue(value string) string {
	h := make([]byte, 64)
	sha3.ShakeSum256(h, []byte(value))
	return fmt.Sprintf("%x", h)
}

func UnindexedKey(key string) string {
	if len(key) == 0 {
		return key
	}
	return strings.Split(key, "[")[0]
}

func FormatSessionIdentifier(logger *zap.Logger, separator string, indexes []int, value string) string {
	parts := strings.Split(value, separator)
	var session string
	for i, index := range indexes {
		if index >= len(parts) {
			logger.Debug("Session index greater than number parts", zap.Int("index", index), zap.Int("parts", len(parts)))
			break
		}
		if i > 0 {
			session += separator
		}
		session += parts[index]
	}
	return session
}

func (pfp *piifilterprocessor) setSessionID(piiElem *PiiElement, filterData *FilterData, value string) {
	// don't override an existing session value
	if len(filterData.SessionID) > 0 {
		return
	}

	filterData.SessionID = value
	if len(piiElem.SessionSeparator) > 0 {
		filterData.SessionID = FormatSessionIdentifier(pfp.logger, piiElem.SessionSeparator, piiElem.SessionIndexes, value)
	}

	if piiElem.Redact != Raw {
		filterData.SessionID = HashValue(filterData.SessionID)
	}
}

// In case if we want to have PiiElement specific redaction configguration, we can pass the bool here from piiElement instead of depending on global value
func (pfp *piifilterprocessor) redactString(value string) (bool, string) {
	switch pfp.redact {
	case Hash:
		h := make([]byte, 64)
		sha3.ShakeSum256(h, []byte(value))
		redacted := fmt.Sprintf("%x", h)
		return false, redacted
	case Redact:
		return true, common.RedactedText
	default:
		return true, common.RedactedText
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
		pfp.logger.Debug("Could not parse media type", zap.Error(err), zap.String("dataType", dataType))
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

func (pfp *piifilterprocessor) addInspectorAttribute(span *tracepb.Span, redactedValues map[string][]*inspector.Value) {
	if len(redactedValues) == 0 {
		return
	}
	httpApiInspection := &pb.HttpApiInspection{}

	pfp.inspectorManager.EvaluateInspectors(httpApiInspection, redactedValues)

	serialized, err := proto.Marshal(httpApiInspection)
	if err != nil {
		pfp.logger.Warn("Problem marshalling Inspector attr object.", zap.Error(err))
		return
	}
	encoded := b64.StdEncoding.EncodeToString(serialized)

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: encoded}}
	span.GetAttributes().AttributeMap[inspectorTag] = pbAttrib
}

func (pfp *piifilterprocessor) addSessionAttribute(span *tracepb.Span, sessionID string) {
	if len(sessionID) == 0 {
		return
	}
	attribMap := span.GetAttributes().AttributeMap
	// don't overwrite an exisiting session id
	if _, ok := attribMap[sessionIDTag]; ok {
		return
	}

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: sessionID}}
	attribMap[sessionIDTag] = pbAttrib
}
