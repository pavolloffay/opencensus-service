package inspector

import (
	"fmt"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

type valueinspector struct {
	logger *zap.Logger
}

func newValueInspector(logger *zap.Logger) inspector {
	return &valueinspector{
		logger: logger,
	}
}

func (ti *valueinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {

	if message == nil {
		ti.logger.Warn("Message is nil")
		return
	}

	if message.MetadataInspection.Value == nil {
		message.MetadataInspection.Value = &pb.Value{}
	}

	pbVal := message.MetadataInspection.Value
	if value.SentOriginal {
		pbVal.Value = fmt.Sprintf("%v", value.OriginalValue)
		pbVal.ValueType = pb.ValueType_RAW
	} else {
		pbVal.Value = value.RedactedValue
		if value.Redacted {
			pbVal.ValueType = pb.ValueType_REDACTED
		} else {
			pbVal.ValueType = pb.ValueType_HASHED
		}
	}
	return
}

var _ inspector = (*valueinspector)(nil)
