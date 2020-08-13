package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_specialchardistinspector_notempty(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: ";:'()*/\\&#%`+<>|\r\n"})
	assert.True(t, len(message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution) == 18)
	for _, value := range message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution {
		assert.True(t, value == 1)
	}
	assert.False(t, message.MetadataInspection.SpecialCharInspection.StartsWithPipe)
}

func Test_specialchardistinspector_empty(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "asdasdas"})
	assert.True(t, len(message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution) == 0)
	assert.False(t, message.MetadataInspection.SpecialCharInspection.StartsWithPipe)

}

func Test_specialchardistinspector_startswithpipe(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "|dsfsddsvds"})
	assert.True(t, len(message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution) == 1)
	for _, value := range message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution {
		assert.True(t, value == 1)
	}
	assert.True(t, message.MetadataInspection.SpecialCharInspection.StartsWithPipe)
}

func Test_specialCharDistInspector_operatorpresent(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "{\"$lt\" : \"100\"}"})
	assert.True(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}

func Test_specialCharDistInspector_operatorabsent(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "{\"key1\":[{\"gt\":\"$test\"}, \"$test1\"],\"lt\" : \"100\"}"})
	assert.False(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}

func Test_specialCharDistInspector_partialjson(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "{\"$lt\" : \"100}"})
	assert.False(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}

func Test_specialchardistinspector_nil(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", nil)
	assert.True(t, len(message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution) == 0)
	assert.False(t, message.MetadataInspection.SpecialCharInspection.StartsWithPipe)
	assert.False(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}

func Test_specialchardistinspector_empty_string(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newSpecialCharDistInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: ""})
	assert.True(t, len(message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution) == 0)
	assert.False(t, message.MetadataInspection.SpecialCharInspection.StartsWithPipe)
	assert.False(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}
