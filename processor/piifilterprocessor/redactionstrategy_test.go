package piifilterprocessor

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type RedactionTest struct {
	Test      string            `json:"test"`
	Redaction RedactionStrategy `json:"redaction-strategy,omitempty"`
}

func Test_redactionstrategy_marshaljson(t *testing.T) {
	redTest1 := RedactionTest{
		Test:      "marshal_json",
		Redaction: Redact,
	}
	redTest1Received, _ := json.Marshal(redTest1)
	assert.True(t, string(redTest1Received) == "{\"test\":\"marshal_json\",\"redaction-strategy\":\"redact\"}")

	redTest2 := RedactionTest{
		Test:      "marshal_json",
		Redaction: Hash,
	}
	redTest2Received, _ := json.Marshal(redTest2)
	assert.True(t, string(redTest2Received) == "{\"test\":\"marshal_json\",\"redaction-strategy\":\"hash\"}")

	redTest3 := RedactionTest{
		Test: "marshal_json",
	}
	redTest3Received, _ := json.Marshal(redTest3)
	assert.True(t, string(redTest3Received) == "{\"test\":\"marshal_json\"}")
}

func Test_redactionstrategy_unmarshaljson(t *testing.T) {
	testStr1 := "{\"test\":\"marshal_json\",\"redaction-strategy\":\"redact\"}"
	testRed1 := RedactionTest{}
	json.Unmarshal([]byte(testStr1), &testRed1)
	assert.True(t, testRed1.Test == "marshal_json")
	assert.True(t, testRed1.Redaction == Redact)

	testStr2 := "{\"test\":\"marshal_json\",\"redaction-strategy\":\"hash\"}"
	testRed2 := RedactionTest{}
	json.Unmarshal([]byte(testStr2), &testRed2)
	assert.True(t, testRed2.Test == "marshal_json")
	assert.True(t, testRed2.Redaction == Hash)

	testStr3 := "{\"test\":\"marshal_json\"}"
	testRed3 := RedactionTest{}
	json.Unmarshal([]byte(testStr3), &testRed3)
	assert.True(t, testRed3.Test == "marshal_json")
	assert.True(t, int(testRed3.Redaction) == 0)
}
