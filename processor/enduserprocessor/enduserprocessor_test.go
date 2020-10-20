package enduserprocessor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/exporter/exportertest"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	hmacSecret = []byte("123")
)

func Test_enduser_authHeader_bearer(t *testing.T) {
	endusers := []Enduser{{
		Key:         "http.request.header.authorization",
		Type:        "authheader",
		Encoding:    "jwt",
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

	user := ep.authHeaderCapture(endusers[0], "Bearer "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue(tokenString), user.session)
}

func Test_enduser_authHeader_complexClaim(t *testing.T) {
	endusers := []Enduser{{
		Key:        "http.request.header.authorization",
		Type:       "authheader",
		Encoding:   "jwt",
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

	user := ep.authHeaderCapture(endusers[0], "Bearer "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, `{"role":{"a":["b","c"]}}`, user.role)
}

func Test_enduser_authHeader_complexClaimPath(t *testing.T) {
	endusers := []Enduser{{
		Key:           "http.request.header.authorization",
		Type:          "authheader",
		Encoding:      "jwt",
		IDClaims:      []string{"data"},
		IDPaths:       []string{"$.uuid"},
		RoleClaims:    []string{"data"},
		RolePaths:     []string{"$.role"},
		ScopeClaims:   []string{"data"},
		ScopePaths:    []string{"$.scope"},
		SessionClaims: []string{"data"},
		SessionPaths:  []string{"$.token"},
	}}

	var complexID interface{}
	err := json.Unmarshal([]byte(`{"uuid": "dave", "role": "user", "scope": "traceable", "token": "abc"}`), &complexID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"data": complexID,
	})

	tokenString, err := token.SignedString(hmacSecret)
	fmt.Println(tokenString)
	assert.Nil(t, err)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.authHeaderCapture(endusers[0], "Bearer "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue("abc"), user.session)
}

func Test_enduser_authHeader_basic(t *testing.T) {
	endusers := []Enduser{{
		Key:  "http.request.header.authorization",
		Type: "authheader",
	}}

	auth := "dave:pw123"
	tokenString := base64.StdEncoding.EncodeToString([]byte(auth))

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.authHeaderCapture(endusers[0], "Basic "+tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "", user.role)
	assert.Equal(t, "", user.scope)
	assert.Equal(t, "", user.session)
}

func Test_enduser_id(t *testing.T) {
	endusers := []Enduser{{
		Key:  "http.request.header.x-user",
		Type: "id",
	}}

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.idCapture(endusers[0], "dave")
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "", user.role)
	assert.Equal(t, "", user.scope)
	assert.Equal(t, "", user.session)
}

func Test_enduser_role(t *testing.T) {
	endusers := []Enduser{{
		Key:  "http.request.header.x-role",
		Type: "role",
	}}

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.roleCapture(endusers[0], "user")
	assert.NotNil(t, user)
	assert.Equal(t, "", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "", user.scope)
	assert.Equal(t, "", user.session)
}

func Test_enduser_scope(t *testing.T) {
	endusers := []Enduser{{
		Key:  "http.request.header.x-scope",
		Type: "scope",
	}}

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.scopeCapture(endusers[0], "traceable")
	assert.NotNil(t, user)
	assert.Equal(t, "", user.id)
	assert.Equal(t, "", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, "", user.session)
}
func Test_enduser_json(t *testing.T) {
	endusers := []Enduser{{
		Key:          "http.response.body",
		Type:         "json",
		IDPaths:      []string{"$.userInfo.name"},
		RolePaths:    []string{"$.userInfo.role"},
		ScopePaths:   []string{"$.userInfo.scope"},
		SessionPaths: []string{"$.token"},
	}}

	jsonStr := string(`
	{
			"userInfo": {
					"name": "dave",
					"role": "user",
					"scope": "traceable"
			},
			"token": "abc"
	}`)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.jsonCapture(endusers[0], jsonStr)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue("abc"), user.session)
}

func Test_enduser_complexJson(t *testing.T) {
	endusers := []Enduser{{
		Key:          "http.response.body",
		Type:         "json",
		IDPaths:      []string{"$.userInfo.name"},
		RolePaths:    []string{"$.userInfo.role"},
		ScopePaths:   []string{"$.userInfo.scope"},
		SessionPaths: []string{"$.token"},
	}}
	jsonStr := string(`
	{
			"userInfo": {
					"name": "dave",
					"role": ["user", "admin"],
					"scope": "traceable"
			},
			"token": "abc"
	}`)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.jsonCapture(endusers[0], jsonStr)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "[\"user\",\"admin\"]", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue("abc"), user.session)
}

func Test_enduser_truncatedJson(t *testing.T) {
	endusers := []Enduser{{
		Key:          "http.response.body",
		Type:         "json",
		IDPaths:      []string{"$.userInfo.name"},
		RolePaths:    []string{"$.userInfo.role"},
		ScopePaths:   []string{"$.userInfo.scope"},
		SessionPaths: []string{"$.token"},
	}}
	jsonStr := string(`
	{
			"userInfo": {
					"name": "dave",
					"role": ["user", "admin"],
					"scope": "traceable"
			},
			"token": "abc"
	`) // note the missing }

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.jsonCapture(endusers[0], jsonStr)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "[\"user\",\"admin\"]", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue("abc"), user.session)
}

func Test_enduser_urlencoded(t *testing.T) {
	endusers := []Enduser{{
		Key:         "http.response.body",
		Type:        "urlencoded",
		IDKeys:      []string{"name"},
		RoleKeys:    []string{"role"},
		ScopeKeys:   []string{"scope"},
		SessionKeys: []string{"session"},
	}}

	v := url.Values{}
	v.Add("name", "dave")
	v.Add("role", "user")
	v.Add("scope", "traceable")
	v.Add("session", "abc")

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.urlencodedCapture(endusers[0], v.Encode())
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue("abc"), user.session)
}

func Test_enduser_cookie(t *testing.T) {
	endusers := []Enduser{{
		Key:         "http.response.header.set-cookie",
		Type:        "cookie",
		IDKeys:      []string{"name"},
		RoleKeys:    []string{"role"},
		ScopeKeys:   []string{"scope"},
		SessionKeys: []string{"session"},
	}}

	cookieStr := "name=dave;role=user;scope=traceable;session=abc"

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.cookieCapture(endusers[0], cookieStr)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue("abc"), user.session)
}

func Test_enduser_cookieJwt(t *testing.T) {
	endusers := []Enduser{{
		Key:         "http.request.header.cookie",
		Type:        "cookie",
		CookieName:  "token",
		Encoding:    "jwt",
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
	cookieStr := "otherCookie=abc;token=" + tokenString

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := ep.cookieCapture(endusers[0], cookieStr)
	assert.NotNil(t, user)
	assert.Equal(t, "dave", user.id)
	assert.Equal(t, "user", user.role)
	assert.Equal(t, "traceable", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue(tokenString), user.session)
}

func Test_enduser_condition(t *testing.T) {
	endusers := []Enduser{{
		Key:  "http.response.body",
		Type: "json",
		Conditions: []Condition{{
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

	assert.Equal(t, "match_name", spanMatch.GetAttributes().AttributeMap["enduser.id"].GetStringValue().Value)
	assert.Nil(t, spanNoMatch.GetAttributes().AttributeMap["enduser.id"])
}

func Test_enduser_authHeader_sessionIndexes(t *testing.T) {
	endusers := []Enduser{{
		Key:              "http.request.header.authorization",
		Type:             "authheader",
		Encoding:         "jwt",
		SessionSeparator: ".",
		SessionIndexes:   []int{0, 2},
	}}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "dave",
		"role":  "user",
		"scope": "traceable",
	})
	tokenString, err := token.SignedString(hmacSecret)
	tokenParts := strings.Split(tokenString, ".")
	assert.Nil(t, err)

	logger := zap.New(zapcore.NewNopCore())
	processor, err := NewTraceProcessor(&exportertest.SinkTraceExporter{}, endusers, logger)
	var ep = processor.(*enduserprocessor)
	assert.Nil(t, err)

	user := user{}
	ep.setSession(endusers[0], &user, tokenString)
	assert.NotNil(t, user)
	assert.Equal(t, "", user.id)
	assert.Equal(t, "", user.role)
	assert.Equal(t, "", user.scope)
	assert.Equal(t, piifilterprocessor.HashValue(tokenParts[0]+"."+tokenParts[2]), user.session)
}
