//+build collector

package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"go.uber.org/zap"
)

type modsecinspector struct {
}

type ModsecConfig struct {
	ConfigDir string `json:"config-dir"`
	FileName  string `json:"file-name"`
	Rules     string `json:"rules"`
}

func NewModsecInspector(logger *zap.Logger, modsecConfig ModsecConfig) *modsecinspector {
	return nil
}

func (mi *modsecinspector) inspect(message *pb.HttpApiInspection, keyToValuesMap map[string][]*Value) {
	return
}
