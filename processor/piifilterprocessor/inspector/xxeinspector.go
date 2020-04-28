package inspector

import (
	"errors"
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

func (xi *xxeinspector) inspect(message *pb.ApiDefinitionInspection, key string, value string) (bool, error) {
	if message == nil {
		return false, errors.New("message is nil.")
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
		return true, nil
	}

	return false, nil
}

var _ Inspector = (*xxeinspector)(nil)
