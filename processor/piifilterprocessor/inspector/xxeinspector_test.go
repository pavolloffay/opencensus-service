package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_xxeinspector_xxeanomaly_exists(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newXXEInspector(logger)
	message := &pb.ApiDefinitionInspection{}

	inspector.inspect(message, "test.key", "<!ENTITY")

	assert.True(t, (message.XxeAnomalies["test.key"] != nil))
	assert.True(t, (message.XxeAnomalies["test.key"].Value == "<!ENTITY"))
	assert.True(t, (message.XxeAnomalies["test.key"].ValueType == pb.ValueType_RAW))
}

func Test_xxeinspector_xxeanomaly_doesnt_exist(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newXXEInspector(logger)
	message := &pb.ApiDefinitionInspection{}

	inspector.inspect(message, "test.key", "34")

	assert.True(t, (message.XxeAnomalies == nil))
}
