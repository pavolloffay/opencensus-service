package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_valueinspector_raw(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newValueInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: 32, SentOriginal: true})

	assert.True(t, message.MetadataInspection.Value.Value == "32")
	assert.True(t, message.MetadataInspection.Value.ValueType == pb.ValueType_RAW)
}

func Test_valueinspector_redacted(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newValueInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: 32, SentOriginal: false, RedactedValue: "***", Redacted: true})

	assert.True(t, message.MetadataInspection.Value.Value == "***")
	assert.True(t, message.MetadataInspection.Value.ValueType == pb.ValueType_REDACTED)
}

func Test_valueinspector_hashed(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newValueInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: 32, SentOriginal: false, RedactedValue: "ashbvfthbvffvhjiuytfghjnbg", Redacted: false})

	assert.True(t, message.MetadataInspection.Value.Value == "ashbvfthbvffvhjiuytfghjnbg")
	assert.True(t, message.MetadataInspection.Value.ValueType == pb.ValueType_HASHED)
}
