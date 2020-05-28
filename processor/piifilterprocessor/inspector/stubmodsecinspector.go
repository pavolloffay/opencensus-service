//+build collector

package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"go.uber.org/zap"
)

type stubmodsecinspector struct {
}

type ModsecConfig struct {
}

func NewModsecInspector(logger *zap.Logger, modsecConfig ModsecConfig) modsecinspector {
	return &stubmodsecinspector{}
}

func (smi *stubmodsecinspector) inspect(message *pb.HttpApiInspection, keyToValuesMap map[string][]*Value) {
	return
}
