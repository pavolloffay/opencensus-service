package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

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

func (li *lengthinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {
	if message == nil {
		li.logger.Warn("Message is nil")
		return
	}

	if value == nil || len(value.OriginalValue) == 0 {
		return
	}

	message.MetadataInspection.Length = int32(len(value.OriginalValue))
	return
}

var _ inspector = (*typeinspector)(nil)
