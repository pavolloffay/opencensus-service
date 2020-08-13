package inspector

import (
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"
	jsoniter "github.com/json-iterator/go"

	"go.uber.org/zap"
)

type specialchardistinspector struct {
	logger       *zap.Logger
	specialChars map[rune]bool
}

func newSpecialCharDistInspector(logger *zap.Logger) inspector {
	specialChars := make(map[rune]bool)
	specialChars[';'] = true
	specialChars[':'] = true
	specialChars['\''] = true
	specialChars['('] = true
	specialChars[')'] = true
	specialChars['*'] = true
	specialChars['/'] = true
	specialChars['\\'] = true
	specialChars['&'] = true
	specialChars['#'] = true
	specialChars['%'] = true
	specialChars['`'] = true
	specialChars['+'] = true
	specialChars['<'] = true
	specialChars['>'] = true
	specialChars['|'] = true
	specialChars['\r'] = true
	specialChars['\n'] = true
	return &specialchardistinspector{
		logger:       logger,
		specialChars: specialChars,
	}
}

func (scdi *specialchardistinspector) nosqlOperatorPresent(value string) bool {
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

func (scdi *specialchardistinspector) processJson(t interface{}) bool {
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

func (scdi *specialchardistinspector) inspect(message *pb.ParamValueInspection, key string, value *Value) {
	if message == nil {
		scdi.logger.Warn("Message is nil")
		return
	}
	if message.MetadataInspection.SpecialCharInspection == nil {
		message.MetadataInspection.SpecialCharInspection = &pb.SpecialCharacterInspection{}
	}

	message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution = make(map[int32]int32)

	if value == nil || len(value.OriginalValue) == 0 {
		return
	}

	if value.OriginalValue[0] == '|' {
		message.MetadataInspection.SpecialCharInspection.StartsWithPipe = true
	}

	message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp = false
	isDollarPresent := false

	for _, runeVal := range value.OriginalValue {
		if runeVal == '$' {
			isDollarPresent = true
		}

		if !scdi.specialChars[runeVal] {
			continue
		}
		runeValAscii := int32(runeVal)
		message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution[runeValAscii] =
			message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution[runeValAscii] + 1
	}

	if isDollarPresent {
		message.MetadataInspection.SpecialCharInspection.ContainsNosqlOp = scdi.nosqlOperatorPresent(value.OriginalValue)
	}

	return
}

var _ inspector = (*specialchardistinspector)(nil)
