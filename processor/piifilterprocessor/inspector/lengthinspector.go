package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

type lengthinspector struct {
	logger *zap.Logger
}

func newLengthInspector(logger *zap.Logger) inspector {
	return &lengthinspector{
		logger: logger,
	}
}

func (ti *lengthinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {
	if message == nil {
		ti.logger.Warn("Message is nil")
		return
	}

	message.MetadataInspection.Length = int32(len(value.OriginalValue))
	return
}

var _ inspector = (*typeinspector)(nil)
