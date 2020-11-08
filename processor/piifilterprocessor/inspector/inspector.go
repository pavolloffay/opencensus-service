package inspector

import (
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"go.uber.org/zap"
)

const (
	queryParamPrefix          = "http.request.query.param."
	requestBodyPrefix         = "http.request.body."
	requestHeaderPrefix       = "http.request.header."
	requestCookiePrefix       = "http.request.cookie."
	responseBodyPrefix        = "http.response.body."
	responseHeaderPrefix      = "http.response.header."
	responseCookiePrefix      = "http.response.cookie."
	rpcRequestBodyPrefix      = "rpc.request.body."
	rpcRequestMetadataPrefix  = "rpc.request.metadata."
	rpcResponseBodyPrefix     = "rpc.response.body."
	rpcResponseMetadataPrefix = "rpc.response.metadata."
)

type paramType int

const (
	unknown paramType = iota
	query
	requestBody
	requestHeader
	requestCookie
	responseBody
	responseHeader
	responseCookie
	rpcRequestBody
	rpcRequestMetadata
	rpcResponseBody
	rpcResponseMetadata
)

// stripParamPrefix identifies the paramType based on the prefix and
// strips it.
func stripPrefix(key string) (string, paramType) {
	prefix := ""
	prefixType := unknown
	switch {
	case strings.HasPrefix(key, queryParamPrefix):
		prefix = queryParamPrefix
		prefixType = query
	case strings.HasPrefix(key, requestBodyPrefix):
		prefix = requestBodyPrefix
		prefixType = requestBody
	case strings.HasPrefix(key, requestHeaderPrefix):
		prefix = requestHeaderPrefix
		prefixType = requestHeader
	case strings.HasPrefix(key, requestCookiePrefix):
		prefix = requestCookiePrefix
		prefixType = requestCookie
	case strings.HasPrefix(key, responseBodyPrefix):
		prefix = responseBodyPrefix
		prefixType = responseBody
	case strings.HasPrefix(key, responseHeaderPrefix):
		prefix = responseHeaderPrefix
		prefixType = responseHeader
	case strings.HasPrefix(key, responseCookiePrefix):
		prefix = responseCookiePrefix
		prefixType = responseCookie
	case strings.HasPrefix(key, rpcRequestBodyPrefix):
		prefix = rpcRequestBodyPrefix
		prefixType = rpcRequestBody
	case strings.HasPrefix(key, rpcRequestMetadataPrefix):
		prefix = rpcRequestMetadataPrefix
		prefixType = rpcRequestMetadata
	case strings.HasPrefix(key, rpcResponseBodyPrefix):
		prefix = rpcResponseBodyPrefix
		prefixType = rpcResponseBody
	case strings.HasPrefix(key, rpcResponseMetadataPrefix):
		prefix = rpcResponseMetadataPrefix
		prefixType = rpcResponseMetadata
	}
	normalizedKey := strings.TrimPrefix(key, prefix)
	return normalizedKey, prefixType
}

// Struct for handling extracted values
type Value struct {
	OriginalValue string
	ValueProto    *pb.Value
}

func NewValue(originalValue string, redacted string, isRedacted bool) *Value {
	val := &Value{
		OriginalValue: originalValue,
		ValueProto:    &pb.Value{},
	}

	if isRedacted {
		val.ValueProto.ValueType = pb.ValueType_VALUE_TYPE_REDACTED
	} else {
		val.ValueProto.Value = redacted
		val.ValueProto.ValueType = pb.ValueType_VALUE_TYPE_HASHED
	}
	return val
}

type inspector interface {
	inspect(message *pb.ParamValueInspection, key string, value *Value)
}

type modsecinspector interface {
	inspect(message *pb.HttpApiInspection, keyToValuesMap map[string][]*Value)
}

type InspectorManager struct {
	logger          *zap.Logger
	inspectors      []inspector
	modsecInspector modsecinspector
}

func NewInspectorManager(logger *zap.Logger, modsecConfig ModsecConfig) *InspectorManager {
	var inspectors []inspector
	inspector := newTypeInspector(logger)
	inspectors = append(inspectors, inspector)
	inspector = newLengthInspector(logger)
	inspectors = append(inspectors, inspector)
	inspector = newSpecialCharDistInspector(logger)
	inspectors = append(inspectors, inspector)

	modsecInspector := NewModsecInspector(logger, modsecConfig)

	return &InspectorManager{
		logger:          logger,
		inspectors:      inspectors,
		modsecInspector: modsecInspector,
	}
}

func addParamValueInspections(message *pb.HttpApiInspection, key string, inspections *pb.ParamValueInspections) {
	normalizedKey, prefixType := stripPrefix(key)
	switch prefixType {
	case query:
		if message.QueryParamInspection == nil {
			message.QueryParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.QueryParamInspection[normalizedKey] = inspections
	case requestBody:
		if message.RequestBodyParamInspection == nil {
			message.RequestBodyParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RequestBodyParamInspection[normalizedKey] = inspections
	case requestHeader:
		if message.RequestHeaderParamInspection == nil {
			message.RequestHeaderParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RequestHeaderParamInspection[normalizedKey] = inspections
	case requestCookie:
		if message.RequestCookieInspection == nil {
			message.RequestCookieInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RequestCookieInspection[normalizedKey] = inspections
	case responseBody:
		if message.ResponseBodyParamInspection == nil {
			message.ResponseBodyParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.ResponseBodyParamInspection[normalizedKey] = inspections
	case responseHeader:
		if message.ResponseHeaderParamInspection == nil {
			message.ResponseHeaderParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.ResponseHeaderParamInspection[normalizedKey] = inspections
	case responseCookie:
		if message.ResponseCookieInspection == nil {
			message.ResponseCookieInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.ResponseCookieInspection[normalizedKey] = inspections
	case rpcRequestBody:
		if message.RpcRequestBodyParamInspection == nil {
			message.RpcRequestBodyParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RpcRequestBodyParamInspection[normalizedKey] = inspections
	case rpcRequestMetadata:
		if message.RpcRequestMetadataParamInspection == nil {
			message.RpcRequestMetadataParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RpcRequestMetadataParamInspection[normalizedKey] = inspections
	case rpcResponseBody:
		if message.RpcResponseBodyParamInspection == nil {
			message.RpcResponseBodyParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RpcResponseBodyParamInspection[normalizedKey] = inspections
	case rpcResponseMetadata:
		if message.RpcResponseMetadataParamInspection == nil {
			message.RpcResponseMetadataParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		message.RpcResponseMetadataParamInspection[normalizedKey] = inspections
	}
}

func (im *InspectorManager) EvaluateInspectors(message *pb.HttpApiInspection, keyToValueMap map[string][]*Value) {
	if im.modsecInspector != nil {
		im.modsecInspector.inspect(message, keyToValueMap)
	}
	for key, values := range keyToValueMap {
		var paramValueInspections []*pb.ParamValueInspection
		for _, value := range values {
			paramValueInspection := &pb.ParamValueInspection{}
			paramValueInspections = append(paramValueInspections, paramValueInspection)
			paramValueInspection.MetadataInspection = &pb.MetadataInspection{}
			paramValueInspection.MetadataInspection.Value = value.ValueProto
			for _, inspector := range im.inspectors {
				inspector.inspect(paramValueInspection, key, value)
			}
		}

		addParamValueInspections(message, key, &pb.ParamValueInspections{
			ParamInspections: paramValueInspections,
		})
	}
}
