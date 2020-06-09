package enduserprocessor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/dgrijalva/jwt-go"
	jsoniter "github.com/json-iterator/go"
	"github.com/yalp/jsonpath"

	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"go.uber.org/zap"
)

const (
	enduserIDAttribute    = "enduser.id"
	enduserRoleAttribute  = "enduser.role"
	enduserScopeAttribute = "enduser.scope"
)

// Condition is the condition that must be matched
// before trying to caputure the user
type Condition struct {
	Key   string `json:"key"`
	Regex string `json:"regex"`
}

// Enduser is the configuration defining where to
// extract enduser data
type Enduser struct {
	Key         string      `mapstructure:"key"`
	Type        string      `mapstructure:"type"`
	Conditions  []Condition `mapstructure:"conditions"`
	IDClaims    []string    `mapstructure:"id_claims"`
	IDPaths     []string    `mapstructure:"id_paths"`
	IDKeys      []string    `mapstructure:"id_keys"`
	RoleClaims  []string    `mapstructure:"role_claims"`
	RolePaths   []string    `mapstructure:"role_paths"`
	RoleKeys    []string    `mapstructure:"role_keys"`
	ScopeClaims []string    `mapstructure:"scope_claims"`
	ScopePaths  []string    `mapstructure:"scope_paths"`
	ScopeKeys   []string    `mapstructure:"scope_keys"`
}

type enduserprocessor struct {
	nextConsumer consumer.TraceConsumer
	logger       *zap.Logger
	endusers     []Enduser
}

// NewTraceProcessor creates a new end user processor which adds enduser attributes to spans when
// data is available
func NewTraceProcessor(nextConsumer consumer.TraceConsumer, endusers []Enduser, logger *zap.Logger) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, errors.New("nextConsumer is nil")
	}

	return &enduserprocessor{
		nextConsumer: nextConsumer,
		logger:       logger,
		endusers:     endusers,
	}, nil
}

func (processor *enduserprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	for _, span := range td.Spans {
		attribMap := span.Attributes.AttributeMap
		if span == nil || span.Attributes == nil || len(attribMap) == 0 {
			continue
		}

		// iterate through enduer locations and see if
		// the keys exist in the span
		for _, enduser := range processor.endusers {
			if attrib, ok := attribMap[enduser.Key]; ok {
				value := attrib.GetStringValue()
				if value == nil {
					continue
				}

				processor.capture(span, enduser, value.Value)
			}
		}
	}

	return processor.nextConsumer.ConsumeTraceData(ctx, td)
}

type user struct {
	id    string
	role  string
	scope string
}

func (processor *enduserprocessor) capture(span *tracepb.Span, enduser Enduser, value string) {
	if !processor.passesConditions(span, enduser.Conditions) {
		return
	}

	var user *user
	switch enduser.Type {
	case "authtoken":
		user = processor.authTokenCapture(enduser, value)
	case "json":
		user = processor.jsonCapture(enduser, value)
	case "urlencoded":
		user = processor.urlencodedCapture(enduser, value)
	case "cookie":
		user = processor.cookieCapture(enduser, value)
	default:
		processor.logger.Warn("Unknown enduser type", zap.String("type", enduser.Type))
	}

	if user == nil {
		return
	}

	if len(user.id) > 0 {
		addSpanAttribute(span, enduserIDAttribute, user.id)
	}

	if len(user.role) > 0 {
		addSpanAttribute(span, enduserRoleAttribute, user.role)
	}

	if len(user.scope) > 0 {
		addSpanAttribute(span, enduserScopeAttribute, user.scope)
	}
}

// only capture the user info if all conditions
// are true.  If an conditions key does not exist
// in the span, that is considered a failed condition
func (processor *enduserprocessor) passesConditions(span *tracepb.Span, conditions []Condition) bool {
	attribMap := span.GetAttributes().AttributeMap

	for _, condition := range conditions {
		attrib, ok := attribMap[condition.Key]
		if !ok {
			return false
		}

		value := attrib.GetStringValue()
		if value == nil {
			return false
		}

		matched, err := regexp.MatchString(condition.Regex, value.Value)
		if err != nil {
			processor.logger.Warn("Could not evaluate enduser condition", zap.Error(err))
			return false
		}
		if !matched {
			return false
		}
	}

	return true
}

func addSpanAttribute(span *tracepb.Span, key string, value string) {
	attribMap := span.GetAttributes().AttributeMap

	// don't overwrite existing attributes
	if _, ok := attribMap[key]; ok {
		return
	}

	pbAttrib := &tracepb.AttributeValue{}
	pbAttrib.Value = &tracepb.AttributeValue_StringValue{StringValue: &tracepb.TruncatableString{Value: value}}

	attribMap[key] = pbAttrib
}

func (processor *enduserprocessor) authTokenCapture(enduser Enduser, value string) *user {
	lcValue := strings.ToLower(value)
	if strings.HasPrefix(lcValue, "bearer ") {
		tokenString := value[7:]
		claims := jwt.MapClaims{}
		_, _, err := new(jwt.Parser).ParseUnverified(tokenString, claims)
		if err != nil {
			processor.logger.Info("Couldn't parse jwt", zap.Error(err))
			return nil
		}

		user := new(user)
		for _, claim := range enduser.IDClaims {
			if id, ok := claims[claim]; ok {
				user.id = processor.jsonToString(id)
				break
			}
		}
		for _, claim := range enduser.RoleClaims {
			if role, ok := claims[claim]; ok {
				user.role = processor.jsonToString(role)
				break
			}
		}
		for _, claim := range enduser.ScopeClaims {
			if scope, ok := claims[claim]; ok {
				user.scope = processor.jsonToString(scope)
				break
			}
		}
		return user
	} else if strings.HasPrefix(lcValue, "basic ") {
		token := value[6:]
		str, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			processor.logger.Info("Could not decode basic token", zap.String("value", value))
			return nil
		}
		creds := bytes.SplitN(str, []byte(":"), 2)
		if len(creds) != 2 {
			processor.logger.Info("Invalid basic token", zap.String("value", value))
			return nil
		}

		user := new(user)
		user.id = string(creds[0])
		return user
	} else {
		processor.logger.Info("Authorization token must be basic or bearer", zap.String("value", value))
	}

	return nil
}

func (processor *enduserprocessor) jsonToString(claim interface{}) string {
	json, err := json.Marshal(claim)
	if err != nil {
		processor.logger.Info("invalid claim", zap.Error(err))
		return ""
	}

	return string(json)
}

func (processor *enduserprocessor) jsonCapture(enduser Enduser, value string) *user {
	var json interface{}
	err := jsoniter.UnmarshalFromString(value, &json)
	if err != nil {
		processor.logger.Info("Could not parse json to capture user", zap.Error(err))
	}

	user := new(user)
	for _, path := range enduser.IDPaths {
		id, err := jsonpath.Read(json, path)
		if err == nil {
			user.id = processor.jsonToString(id)
			break
		}
	}
	for _, path := range enduser.RolePaths {
		role, err := jsonpath.Read(json, path)
		if err == nil {
			user.role = processor.jsonToString(role)
			break
		}
	}
	for _, path := range enduser.ScopePaths {
		scope, err := jsonpath.Read(json, path)
		if err == nil {
			user.scope = processor.jsonToString(scope)
			break
		}
	}
	return user
}

func (processor *enduserprocessor) urlencodedCapture(enduser Enduser, value string) *user {
	params, err := url.ParseQuery(value)
	if err != nil {
		processor.logger.Info("Could not parse urlencoded to capture user", zap.Error(err))
	}

	user := new(user)
	for _, key := range enduser.IDKeys {
		if values, ok := params[key]; ok {
			for _, value := range values {
				if len(value) > 0 {
					user.id = value
					break
				}
			}
		}
		if len(user.id) > 0 {
			break
		}
	}
	for _, key := range enduser.RoleKeys {
		if values, ok := params[key]; ok {
			for _, value := range values {
				if len(value) > 0 {
					user.role = value
				}
			}
		}
		if len(user.role) > 0 {
			break
		}
	}
	for _, key := range enduser.ScopeKeys {
		if values, ok := params[key]; ok {
			for _, value := range values {
				if len(value) > 0 {
					user.scope = value
				}
			}
		}
		if len(user.scope) > 0 {
			break
		}
	}
	return user
}

func (processor *enduserprocessor) cookieCapture(enduser Enduser, value string) *user {
	header := http.Header{}
	header.Add("Cookie", value)
	request := http.Request{Header: header}
	cookies := request.Cookies()

	user := new(user)
	for _, key := range enduser.IDKeys {
		for _, cookie := range cookies {
			if cookie.Name == key {
				user.id = cookie.Value
				break
			}
		}
		if len(user.id) > 0 {
			break
		}
	}
	for _, key := range enduser.RoleKeys {
		for _, cookie := range cookies {
			if cookie.Name == key {
				user.role = cookie.Value
				break
			}
		}
		if len(user.role) > 0 {
			break
		}
	}
	for _, key := range enduser.ScopeKeys {
		for _, cookie := range cookies {
			if cookie.Name == key {
				user.scope = cookie.Value
				break
			}
		}
		if len(user.scope) > 0 {
			break
		}
	}
	return user
}
