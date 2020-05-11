package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

type typeinspector struct {
	logger *zap.Logger
}

const xxeStr = "<!ENTITY"

func newTypeInspector(logger *zap.Logger) inspector {
	return &typeinspector{
		logger: logger,
	}
}

func (xi *typeinspector) inspect(message *pb.ParamValueInspection, key string, value interface{}) {

	if message == nil {
		xi.logger.Warn("Message is nil")
		return
	}

	var paramType pb.ParamValueType

	switch value.(type) {
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
