//+build collector_modsec

package inspector

import (
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/generated/main/go/ai/traceable/platform/apiinspection/v1"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_ModsecInspector_ruleMatchVerification(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	config := ModsecConfig{
		Rules: `
		SecRule ARGS:param1 "test" "id:1,phase:1,deny,msg:'test rule',logdata:'Matched %{MATCHED_VAR_NAME}'"
		SecRule ARGS:param2 "attack" "id:2,phase:2,msg:'test rule2',logdata:'something',tag:'paranoia-level/3'"
		`,
	}
	inspector := NewModsecInspector(logger, config)
	assert.True(t, inspector != nil)

	testAttrs := make(map[string][]*Value)
	testAttrs["http.url"] = append(make([]*Value, 0), &Value{OriginalValue: "/test.pl?param1=test&param2=attack"})
	testAttrs["http.method"] = append(make([]*Value, 0), &Value{OriginalValue: "GET"})

	message := &pb.HttpApiInspection{}
	inspector.inspect(message, testAttrs)

	assert.True(t, message.AnomalyInspection != nil)
	assert.True(t, len(message.AnomalyInspection.ModSecAnomalies) == 2)

	assert.True(t, message.AnomalyInspection.ModSecAnomalies[0].Id == "1")
	assert.True(t, message.AnomalyInspection.ModSecAnomalies[0].RuleMessage == "test rule")
	assert.True(t, message.AnomalyInspection.ModSecAnomalies[0].MatchMessage == "Matched ARGS:param1")
	assert.True(t, message.AnomalyInspection.ModSecAnomalies[0].ParanoiaLevel == 1)

	assert.True(t, message.AnomalyInspection.ModSecAnomalies[1].Id == "2")
	assert.True(t, message.AnomalyInspection.ModSecAnomalies[1].RuleMessage == "test rule2")
	assert.True(t, message.AnomalyInspection.ModSecAnomalies[1].MatchMessage == "something")
	assert.True(t, message.AnomalyInspection.ModSecAnomalies[1].ParanoiaLevel == 3)
}

func Test_ModsecInspector_multiValueKey(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	config := ModsecConfig{
		Rules: `
		SecRule ARGS|ARGS_NAMES "@detectSQLi" "id:100"
		`,
	}
	inspector := NewModsecInspector(logger, config)
	assert.True(t, inspector != nil)

	testAttrs := make(map[string][]*Value)
	testAttrs["http.request.body.login"] = append(append(make([]*Value, 0), &Value{OriginalValue: "this"}), &Value{OriginalValue: "' or '1'='1"})

	message := &pb.HttpApiInspection{}
	inspector.inspect(message, testAttrs)

	assert.True(t, message.AnomalyInspection != nil)
	assert.True(t, len(message.AnomalyInspection.ModSecAnomalies) == 1)

	assert.True(t, message.AnomalyInspection.ModSecAnomalies[0].Id == "100")
}
