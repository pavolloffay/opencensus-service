package inspector

import (
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

const (
	queryParamPrefix     = "http.request.query.param."
	requestBodyPrefix    = "http.request.body."
	requestHeaderPrefix  = "http.request.header."
	requestCookiePrefix  = "http.request.cookie."
	responseBodyPrefix   = "http.response.body."
	responseHeaderPrefix = "http.response.header."
	responseCookiePrefix = "http.response.cookie."
)

// Struct for handling extracted values
type Value struct {
	OriginalValue string
	ValueProto    *pb.Value
}

func NewValue(originalValue string, sentOriginal bool, redacted string, isRedacted bool) *Value {
	val := &Value{
		OriginalValue: originalValue,
		ValueProto:    &pb.Value{},
	}

	if sentOriginal {
		val.ValueProto.Value = originalValue
		val.ValueProto.ValueType = pb.ValueType_RAW
	} else {
		val.ValueProto.Value = redacted
		if isRedacted {
			val.ValueProto.ValueType = pb.ValueType_REDACTED
		} else {
			val.ValueProto.ValueType = pb.ValueType_HASHED
		}
	}
	return val
}

type inspector interface {
	inspect(message *pb.ParamValueInspection, key string, value *Value)
}

type InspectorManager struct {
	logger     *zap.Logger
	inspectors []inspector
}

func NewInspectorManager(logger *zap.Logger) *InspectorManager {
	var inspectors []inspector
	inspector := newTypeInspector(logger)
	inspectors = append(inspectors, inspector)
	inspector = newLengthInspector(logger)
	inspectors = append(inspectors, inspector)
	inspector = newSpecialCharDistInspector(logger)
	inspectors = append(inspectors, inspector)

	return &InspectorManager{
		logger:     logger,
		inspectors: inspectors,
	}
}

func addParamValueInspections(message *pb.HttpApiInspection, key string, inspections *pb.ParamValueInspections) {
	switch {
	case strings.HasPrefix(key, queryParamPrefix):
		if message.QueryParamInspection == nil {
			message.QueryParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, queryParamPrefix)
		message.QueryParamInspection[normalizedKey] = inspections
	case strings.HasPrefix(key, requestBodyPrefix):
		if message.RequestBodyParamInspection == nil {
			message.RequestBodyParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, requestBodyPrefix)
		message.RequestBodyParamInspection[normalizedKey] = inspections
	case strings.HasPrefix(key, requestHeaderPrefix):
		if message.RequestHeaderParamInspection == nil {
			message.RequestHeaderParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, requestHeaderPrefix)
		message.RequestHeaderParamInspection[normalizedKey] = inspections
	case strings.HasPrefix(key, requestCookiePrefix):
		if message.RequestCookieInspection == nil {
			message.RequestCookieInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, requestCookiePrefix)
		message.RequestCookieInspection[normalizedKey] = inspections
	case strings.HasPrefix(key, responseBodyPrefix):
		if message.ResponseBodyParamInspection == nil {
			message.ResponseBodyParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, responseBodyPrefix)
		message.ResponseBodyParamInspection[normalizedKey] = inspections
	case strings.HasPrefix(key, responseHeaderPrefix):
		if message.ResponseHeaderParamInspection == nil {
			message.ResponseHeaderParamInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, responseHeaderPrefix)
		message.ResponseHeaderParamInspection[normalizedKey] = inspections
	case strings.HasPrefix(key, responseCookiePrefix):
		if message.ResponseCookieInspection == nil {
			message.ResponseCookieInspection = make(map[string]*pb.ParamValueInspections)
		}
		normalizedKey := strings.TrimPrefix(key, responseCookiePrefix)
		message.ResponseCookieInspection[normalizedKey] = inspections
	}
}

func (im *InspectorManager) EvaluateInspectors(message *pb.HttpApiInspection, keyToValueMap map[string][]*Value) {
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
