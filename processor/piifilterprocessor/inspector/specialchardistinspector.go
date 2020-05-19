package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-inspection/ai/traceable/platform/apiinspection/v1"

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
	return
}

var _ inspector = (*specialchardistinspector)(nil)
