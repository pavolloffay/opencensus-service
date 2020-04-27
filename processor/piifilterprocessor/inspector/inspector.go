package inspector

import (
	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/api-definition/ai/traceable/platform/apidefinition/v1"
)

type Inspector interface {
      Inspect(message *pb.ApiDefinitionInspection, key string, value string) error
}
