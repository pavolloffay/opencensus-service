package xxeinspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_xxeinspector_xxeanomaly_exists(t *testing.T) {
  logger := zap.New(zapcore.NewNopCore())
  inspector, _ := NewInspector(nil, logger)
  message := &pb.ApiDefinitionInspection{}

  inspector.Inspect(message, "test.key", "<!ENTITY")

  assert.True(t, (message.XxeAnomalies["test.key"] != nil))
}

func Test_xxeinspector_xxeanomaly_doesnt_exist(t *testing.T) {
  logger := zap.New(zapcore.NewNopCore())
  inspector, _ := NewInspector(nil, logger)
  message := &pb.ApiDefinitionInspection{}

  inspector.Inspect(message, "test.key", "34")

  assert.True(t, (message.XxeAnomalies == nil))
}