package inspector

import (
	"errors"
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	// "github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor/inspector"
	"go.uber.org/zap"
)

type xxeinspector struct {
	nextInspector Inspector
	logger        *zap.Logger
}

const xxeStr = "<!ENTITY"

func NewInspector(nextInspector Inspector, logger *zap.Logger) (Inspector, error) {
	return &xxeinspector{
		nextInspector: nextInspector,
		logger:        logger,
	}, nil
}

func (xi *xxeinspector) Inspect(message *pb.ApiDefinitionInspection, key string, value string) (bool, error) {
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
	} else if xi.nextInspector != nil {
		// Should this be else if?
		return xi.nextInspector.Inspect(message, key, value)
	}

	return false, nil
}

var _ Inspector = (*xxeinspector)(nil)
