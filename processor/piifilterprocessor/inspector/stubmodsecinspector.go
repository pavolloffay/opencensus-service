//+build collector

package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

type stupmodsecinspector struct {
}

type ModsecConfig struct {
}

func NewModsecInspector(logger *zap.Logger, modsecConfig ModsecConfig) modsecinspector {
	return &stupmodsecinspector{}
}

func (smi *stupmodsecinspector) inspect(message *pb.HttpApiInspection, keyToValuesMap map[string][]*Value) {
	return
}
