package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_typeinspector_int(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newTypeInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "32"})

	assert.True(t, message.MetadataInspection.Type == pb.ParamValueType_PARAM_VALUE_TYPE_INTEGER)
}

func Test_typeinspector_float(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newTypeInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "32.1"})

	assert.True(t, message.MetadataInspection.Type == pb.ParamValueType_PARAM_VALUE_TYPE_FLOAT)
}

func Test_typeinspector_bool(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newTypeInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "true"})

	assert.True(t, message.MetadataInspection.Type == pb.ParamValueType_PARAM_VALUE_TYPE_BOOLEAN)
}

func Test_typeinspector_string(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newTypeInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "value"})

	assert.True(t, message.MetadataInspection.Type == pb.ParamValueType_PARAM_VALUE_TYPE_STRING)
}
