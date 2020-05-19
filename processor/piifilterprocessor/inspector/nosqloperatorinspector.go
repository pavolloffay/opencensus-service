package inspector

import (
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
	jsoniter "github.com/json-iterator/go"

	"go.uber.org/zap"
)

type nosqloperatorinspector struct {
	logger       *zap.Logger
	specialChars map[rune]bool
}

func newNoSqlOperatorInspector(logger *zap.Logger) inspector {
	return &nosqloperatorinspector{
		logger: logger,
	}
}

func (scdi *nosqloperatorinspector) nosqlOperatorPresent(value string) bool {
	scdi.logger.Debug("Parsing json", zap.String("json", value))

	var parsed interface{}
	err := jsoniter.UnmarshalFromString(value, &parsed)
	if err != nil {
		scdi.logger.Debug("Problem parsing json", zap.Error(err), zap.String("json", value))
		return false
	}

	isPresent := scdi.processJson(parsed)

	return isPresent

}

func (scdi *nosqloperatorinspector) processJson(t interface{}) bool {
	switch tt := t.(type) {
	case []interface{}:
		for _, v := range tt {
			isPresent := scdi.processJson(v)
			if isPresent {
				return true
			}
		}
	case map[string]interface{}:
		for k, v := range tt {
			if strings.HasPrefix(k, "$") {
				return true
			}
			isPresent := scdi.processJson(v)
			if isPresent {
				return true
			}
		}
	case interface{}:
		return false
	}
	return false
}

func (scdi *nosqloperatorinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {
	if message == nil {
		scdi.logger.Warn("Message is nil")
		return
	}
	if message.MetadataInspection.SpecialCharInspection == nil {
		message.MetadataInspection.SpecialCharInspection = &pb.SpecialCharacterInspection{}
	}

	message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp = false

	if strings.ContainsRune(value.OriginalValue, '$') {
		message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp = scdi.nosqlOperatorPresent(value.OriginalValue)
	}

	return
}

var _ inspector = (*nosqloperatorinspector)(nil)
