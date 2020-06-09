package enduserprocessor

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	hmacSecret = []byte("123")
)

func Test_enduser_authToken_bearer(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:         "http.request.header.authorization",
		Type:        "authtoken",
		IDClaims:    []string{"sub"},
		RoleClaims:  []string{"role"},
		ScopeClaims: []string{"scope"},
	}}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "dave",
		"role":  "user",
		"scope": "traceable",
	})
	tokenString, err := token.SignedString(hmacSecret)
	assert.Nil(t, err)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.authTokenCapture(endusers[0], "Bearer "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, "\"dave\"", user.id)
	assert.Equal(t, "\"user\"", user.role)
	assert.Equal(t, "\"traceable\"", user.scope)
}

func Test_enduser_authToken_complexClaim(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:        "http.request.header.authorization",
		Type:       "authtoken",
		RoleClaims: []string{"role"},
	}}

	var complexRole interface{}
	err := json.Unmarshal([]byte(`{"role": {"a": ["b", "c"]}}`), &complexRole)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": complexRole,
	})
	tokenString, err := token.SignedString(hmacSecret)
	assert.Nil(t, err)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.authTokenCapture(endusers[0], "Bearer "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, `{"role":{"a":["b","c"]}}`, user.role)
}

func Test_enduser_authToken_basic(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:  "http.request.header.authorization",
		Type: "authtoken",
	}}

	auth := "dave:pw123"
	tokenString := base64.StdEncoding.EncodeToString([]byte(auth))

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.authTokenCapture(endusers[0], "Basic "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "", user.role)
	assert.Equal(t, "", user.scope)
}

func Test_enduser_json(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:        "http.response.body",
		Type:       "json",
		IDPaths:    []string{"$.userInfo.name"},
		RolePaths:  []string{"$.userInfo.role"},
		ScopePaths: []string{"$.userInfo.scope"},
	}}

	jsonStr := string(`
	{
			"a": "b",
			"userInfo": {
					"name": "dave",
					"role": "user",
					"scope": "traceable"
			},
			"name": "bob"
	}`)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.jsonCapture(endusers[0], jsonStr)
	assert.NotNil(t, user)
	assert.Equal(t, "\"dave\"", user.id)
	assert.Equal(t, "\"user\"", user.role)
	assert.Equal(t, "\"traceable\"", user.scope)
}

func Test_enduser_complexJson(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:        "http.response.body",
		Type:       "json",
		IDPaths:    []string{"$.userInfo.name"},
		RolePaths:  []string{"$.userInfo.role"},
		ScopePaths: []string{"$.userInfo.scope"},
	}}
	jsonStr := string(`
	{
			"a": "b",
			"userInfo": {
					"name": "dave",
					"role": ["user", "admin"],
					"scope": "traceable"
			},
			"name": "bob"
	}`)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.jsonCapture(endusers[0], jsonStr)
	assert.NotNil(t, user)
	assert.Equal(t, "\"dave\"", user.id)
	assert.Equal(t, "[\"user\",\"admin\"]", user.role)
	assert.Equal(t, "\"traceable\"", user.scope)
}

func Test_enduser_urlencoded(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:       "http.response.body",
		Type:      "urlencoded",
		IDKeys:    []string{"name"},
		RoleKeys:  []string{"role"},
		ScopeKeys: []string{"scope"},
	}}

	v := url.Values{}
	v.Add("name", "dave")
	v.Add("role", "user")
	v.Add("scope", "traceable")

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.urlencodedCapture(endusers[0], v.Encode())
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
}

func Test_enduser_cookie(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:       "http.response.header.set-cookie",
		Type:      "cookie",
		IDKeys:    []string{"name"},
		RoleKeys:  []string{"role"},
		ScopeKeys: []string{"scope"},
	}}

	cookieStr := "name=dave;role=user;scope=traceable"

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.cookieCapture(endusers[0], cookieStr)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
}

func Test_enduser_condition(t *testing.T) {
	endusers := []Enduser{Enduser{
		Key:  "http.response.body",
		Type: "json",
		Conditions: []Condition{Condition{
			Key:   "http.url",
			Regex: "login",
		}},
		IDPaths: []string{"$.userInfo.name"},
	}}

	jsonMatchStr := string(`
	{
			"userInfo": {
					"name": "match_name"
	}`)

	jsonNoMatchStr := string(`
	{
			"userInfo": {
					"name": "no_match_name"
			}
	}`)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	assert.Nil(t, err)

	spanMatch := tracepb.Span{
		Name: &tracepb.TruncatableString{Value: "span_match"},
		Attributes: &tracepb.Span_Attributes{
			AttributeMap: map[string]*tracepb.AttributeValue{
				"http.response.body": {
					Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: jsonMatchStr}},
				},
				"http.url": {
					Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "http://localhost/login"}},
				},
			},
		},
	}
	spanNoMatch := tracepb.Span{
		Name: &tracepb.TruncatableString{Value: "span_no_match"},
		Attributes: &tracepb.Span_Attributes{
			AttributeMap: map[string]*tracepb.AttributeValue{
				"http.response.body": {
					Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: jsonNoMatchStr}},
				},
				"http.url": {
					Value: &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: "http://localhost/foo"}},
				},
			},
		},
	}

	td := data.TraceData{
		Spans: []*tracepb.Span{&spanMatch, &spanNoMatch},
	}

	err = processor.ConsumeTraceData(nil, td)
	assert.Nil(t, err)

	assert.Equal(t, "\"match_name\"", spanMatch.GetAttributes().AttributeMap["enduser.id"].GetStringValue().Value)
	assert.Nil(t, spanNoMatch.GetAttributes().AttributeMap["enduser.id"])
}
