package xxeinspector

import (
	"errors"
	"strings"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor"
	"go.uber.org/zap"
)

type xxeinspector struct {
  nextInspector piifilterprocessor.Inspector
	logger       *zap.Logger
}

const xxeStr = "<!ENTITY"

func NewInspector(nextInspector piifilterprocessor.Inspector, logger *zap.Logger) (piifilterprocessor.Inspector, error) {
  return &xxeinspector{
    nextInspector: nextInspector,
		logger:       logger,
  }, nil
}

func (xi *xxeinspector) Inspect(message *pb.ApiDefinitionInspection, key string, value string) error {
  if message == nil {
    return errors.New("message is nil.")
  }

  if strings.Contains(value, xxeStr) {
    xi.logger.Debug("Found XXEAnomaly")
    xa := &pb.XxeAnomaly {
      Value: value,
      ValueType: pb.ValueType_RAW,
    }
    if message.XxeAnomalies == nil {
      message.XxeAnomalies = make(map[string]*pb.XxeAnomaly)
    }
    message.XxeAnomalies[key] = xa
  } else if xi.nextInspector != nil {
    // Should this be else if?
    return xi.nextInspector.Inspect(message, key, value)
  }

  return nil
}

var _ piifilterprocessor.Inspector = (*xxeinspector)(nil)