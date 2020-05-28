//+build collector_modsec

package modsec

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ModsecLib_ruleMatchVerification(t *testing.T) {
	lib := NewModsecLib()
	lib.Init()
	rule := `
	SecRule ARGS:param1 "test" "id:1,phase:1,deny,msg:'test rule',logdata:'Matched %{MATCHED_VAR_NAME}'"
	SecRule ARGS:param2 "attack" "id:2,phase:2,msg:'test rule2',logdata:'something',tag:'paranoia-level/3'"
	`
	err := lib.NewRuleEngineByRules(rule)
	assert.True(t, err == nil)

	testAttrs := make(map[string]string)
	testAttrs["http.url"] = "/test.pl?param1=test&param2=attack"
	testAttrs["http.method"] = "GET"
	testAttrs["http.response.status_code"] = "1.1"

	ret, err := lib.ProcessAttributes(testAttrs)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 2)

	assert.True(t, ret[0].RuleId == "1")
	assert.True(t, ret[0].RuleMessage == "test rule")
	assert.True(t, ret[0].MatchMessage == "Matched ARGS:param1")
	assert.True(t, ret[0].ParanoiaLevel == 1)

	assert.True(t, ret[1].RuleId == "2")
	assert.True(t, ret[1].RuleMessage == "test rule2")
	assert.True(t, ret[1].MatchMessage == "something")
	assert.True(t, ret[1].ParanoiaLevel == 3)

	lib.CleanupRuleEngine()
}

func Test_ModsecLib_UriMatch(t *testing.T) {
	lib := NewModsecLib()
	lib.Init()
	rule := `SecRule REQUEST_URI "test" "id:1"`
	err := lib.NewRuleEngineByRules(rule)
	assert.True(t, err == nil)

	testAttrs := make(map[string]string)
	testAttrs["http.url"] = "/script.pl?param1=test"
	testAttrs["http.method"] = "GET"
	testAttrs["http.response.status_code"] = "1.1"

	ret, err := lib.ProcessAttributes(testAttrs)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 1)

	assert.True(t, ret[0].RuleId == "1")

	lib.CleanupRuleEngine()
}

func Test_ModsecLib_ArgMatch(t *testing.T) {
	lib := NewModsecLib()
	lib.Init()
	rule := `SecRule ARGS|ARGS_NAMES "@detectSQLi" "id:100"`
	err := lib.NewRuleEngineByRules(rule)
	assert.True(t, err == nil)

	testAttrs := make(map[string]string)
	testAttrs["http.request.body.login"] = "' or '1'='1"

	ret, err := lib.ProcessAttributes(testAttrs)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 1)

	assert.True(t, ret[0].RuleId == "100")

	testAttrs2 := make(map[string]string)
	testAttrs2["http.request.body.10; drop table users --"] = "good value"

	ret, err = lib.ProcessAttributes(testAttrs2)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 1)

	assert.True(t, ret[0].RuleId == "100")

	lib.CleanupRuleEngine()
}

func Test_ModsecLib_ReqHeaderMatch(t *testing.T) {
	lib := NewModsecLib()
	lib.Init()
	rule := `SecRule REQUEST_HEADERS:Host "attacker" "id:20"`
	err := lib.NewRuleEngineByRules(rule)
	assert.True(t, err == nil)

	testAttrs := make(map[string]string)
	testAttrs["http.request.header.Host"] = "attacker"

	ret, err := lib.ProcessAttributes(testAttrs)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 1)

	assert.True(t, ret[0].RuleId == "20")

	lib.CleanupRuleEngine()
}

func Test_ModsecLib_ResHeaderMatch(t *testing.T) {
	lib := NewModsecLib()
	lib.Init()
	rule := `SecRule RESPONSE_HEADERS:X-Cache "MISS" "id:55"`
	err := lib.NewRuleEngineByRules(rule)
	assert.True(t, err == nil)

	testAttrs := make(map[string]string)
	testAttrs["http.response.header.X-Cache"] = "MISS"

	ret, err := lib.ProcessAttributes(testAttrs)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 1)

	assert.True(t, ret[0].RuleId == "55")

	lib.CleanupRuleEngine()
}

func Test_ModsecLib_ResStatusMatch(t *testing.T) {
	lib := NewModsecLib()
	lib.Init()
	rule := `SecRule RESPONSE_STATUS "^[45]" "phase:3,id:58,t:none"`
	err := lib.NewRuleEngineByRules(rule)
	assert.True(t, err == nil)

	testAttrs := make(map[string]string)
	testAttrs["http.response.status_code"] = "453"

	ret, err := lib.ProcessAttributes(testAttrs)
	if err != nil {
		fmt.Println(err)
	}

	assert.True(t, len(ret) == 1)

	assert.True(t, ret[0].RuleId == "58")

	lib.CleanupRuleEngine()
}
