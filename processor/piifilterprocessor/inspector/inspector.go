package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	"go.uber.org/zap"
)

type inspector interface {
	inspect(message *pb.ApiDefinitionInspection, key string, value string) bool
}

func EvaluateInspectors(inspectors []inspector, message *pb.ApiDefinitionInspection, key string, value string) {
	for _, inspector := range inspectors {
		hasAnomalies := inspector.inspect(message, key, value)
		if hasAnomalies {
			break
		}
	}
	return
}

type InspectorManager struct {
	logger     *zap.Logger
	inspectors []inspector
}

func NewInspectorManager(logger *zap.Logger) *InspectorManager {
	var inspectors []inspector
	inspector, _ := newXXEInspector(logger)
	inspectors = append(inspectors, inspector)

	return &InspectorManager{
		logger:     logger,
		inspectors: inspectors,
	}
}

func (im *InspectorManager) EvaluateInspectors(message *pb.ApiDefinitionInspection, key string, value string) {
	for _, inspector := range im.inspectors {
		hasAnomalies := inspector.inspect(message, key, value)
		if hasAnomalies {
			im.logger.Debug("Found Anomaly. Breaking from the loop.")
			break
		}
	}
	return
}
