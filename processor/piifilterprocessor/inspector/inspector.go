package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	"go.uber.org/zap"
)

type Inspector interface {
	inspect(message *pb.ApiDefinitionInspection, key string, value string) bool
}

func InitializeInspectors(logger *zap.Logger) []Inspector {
	var inspectors []Inspector
	inspector, _ := newXXEInspector(logger)
	inspectors = append(inspectors, inspector)
	return inspectors
}

func EvaluateInspectors(inspectors []Inspector, message *pb.ApiDefinitionInspection, key string, value string) {
	for _, inspector := range inspectors {
		hasAnomalies := inspector.inspect(message, key, value)
		if hasAnomalies {
			break
		}
	}
	return
}
