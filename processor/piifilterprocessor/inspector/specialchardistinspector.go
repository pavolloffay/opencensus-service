package inspector

import (
	"fmt"
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"
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
	fmt.Println(value)

	if len(value) == 0 {
		return false
	}

	var parsed interface{}
	err := jsoniter.UnmarshalFromString(value, &parsed)
	if err != nil {
		scdi.logger.Info("Problem parsing json", zap.Error(err), zap.String("json", value))
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
				fmt.Println("Found operator in key: ", k)
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

	if value.OriginalValue[0] == '|' {
		message.MetadataInspection.SpecialCharInspection.StartsWithPipe = true
	}

	for _, runeVal := range value.OriginalValue {
		if !scdi.specialChars[runeVal] {
			continue
		}
		runeValAscii := int32(runeVal)
		message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution[runeValAscii] =
			message.MetadataInspection.SpecialCharInspection.SpecialCharDistribution[runeValAscii] + 1
	}
	if strings.ContainsRune(value.OriginalValue, '$') {
		scdi.nosqlOperatorPresent(value.OriginalValue)
	}

	return
}

var _ inspector = (*specialchardistinspector)(nil)
