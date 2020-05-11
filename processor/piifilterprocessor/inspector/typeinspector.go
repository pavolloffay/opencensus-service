package inspector

import (
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

func (ti *typeinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {

	if message == nil {
		ti.logger.Warn("Message is nil")
		return
	}

	var paramType pb.ParamValueType

	switch value.OriginalValue.(type) {
	case bool:
		paramType = pb.ParamValueType_BOOLEAN
	case int, int8, int64, uint, uint8, uint16, uint32, uint64:
		paramType = pb.ParamValueType_INTEGER
	case float32, float64:
		paramType = pb.ParamValueType_FLOAT
	case rune:
		paramType = pb.ParamValueType_CHAR
	case string:
		paramType = pb.ParamValueType_STRING
	default:
		paramType = pb.ParamValueType_UNKNOWN
	}
	message.MetadataInspection.Type = paramType
	return
}

var _ inspector = (*typeinspector)(nil)
