package inspector

import (
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	// "github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/inspector"
	"go.uber.org/zap"
)

type xxeinspector struct {
	logger *zap.Logger
}

const xxeStr = "<!ENTITY"

func newXXEInspector(logger *zap.Logger) (Inspector, error) {
	return &xxeinspector{
		logger: logger,
	}, nil
}

func (xi *xxeinspector) inspect(message *pb.ApiDefinitionInspection, key string, value string) bool {
	if message == nil {
		xi.logger.Warn("Message is nil")
		return false
	}

	if strings.Contains(value, xxeStr) {
		xi.logger.Debug("Found XXEAnomaly")
		xa := &pb.XxeAnomaly{
			Value:     value,
			ValueType: pb.ValueType_RAW,
		}
		if message.XxeAnomalies == nil {
			message.XxeAnomalies = make(map[string]*pb.XxeAnomaly)
		}
		message.XxeAnomalies[key] = xa
		return true
	}

	return false
}

var _ Inspector = (*xxeinspector)(nil)
