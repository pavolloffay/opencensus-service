package inspector

import (
	"strconv"
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

type typeinspector struct {
	logger *zap.Logger
}

func newTypeInspector(logger *zap.Logger) inspector {
	return &typeinspector{
		logger: logger,
	}
}

func isBool(value string) bool {
	isBool := (strings.EqualFold("true", value) || strings.EqualFold("false", value))
	return isBool
}

func isInteger(value string) bool {
	_, err := strconv.ParseInt(value, 0, 64)
	if err != nil {
		return false
	}
	return true
}

func isFloat(value string) bool {
	_, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	return true
}

func (ti *typeinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {
	if message == nil {
		ti.logger.Warn("Message is nil")
		return
	}

	var paramType pb.ParamValueType

	switch {
	case isBool(value.OriginalValue):
		paramType = pb.ParamValueType_BOOLEAN
	case isInteger(value.OriginalValue):
		paramType = pb.ParamValueType_INTEGER
	case isFloat(value.OriginalValue):
		paramType = pb.ParamValueType_FLOAT
	default:
		paramType = pb.ParamValueType_STRING
	}

	message.MetadataInspection.Type = paramType
	return
}

var _ inspector = (*typeinspector)(nil)
