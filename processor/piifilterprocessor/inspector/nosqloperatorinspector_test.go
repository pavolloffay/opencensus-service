package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_nosqloperatorinspector_operatorpresent(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newNoSqlOperatorInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "{\"$lt\" : \"100\"}"})
	assert.True(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}

func Test_nosqloperatorinspector_operatorabsent(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newNoSqlOperatorInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "{\"key1\":[{\"gt\":\"$test\"}, \"$test1\"],\"lt\" : \"100\"}"})
	assert.False(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}

func Test_nosqloperatorinspector_partialjson(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	inspector := newNoSqlOperatorInspector(logger)
	message := &pb.ParamValueInspection{}
	message.MetadataInspection = &pb.MetadataInspection{}

	inspector.inspect(message, "test.key", &Value{OriginalValue: "{\"$lt\" : \"100}"})
	assert.False(t, message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp)
}
