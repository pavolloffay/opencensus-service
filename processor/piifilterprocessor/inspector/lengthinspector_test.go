package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_lengthinspector_notempty(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newLengthInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "32"})

	assert.True(t, message.MetadataInspection.Length == 2)
}

func Test_lengthinspector_empty(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newLengthInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: ""})

	assert.True(t, message.MetadataInspection.Length == 0)
}
