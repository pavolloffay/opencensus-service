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

	"github.com/PaesslerAG/jsonpath"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/dgrijalva/jwt-go"
	jsoniter "github.com/json-iterator/go"

	"github.com/census-instrumentation/opencensus-service/consumer"
	"github.com/census-instrumentation/opencensus-service/data"
	"github.com/census-instrumentation/opencensus-service/processor"
	"github.com/census-instrumentation/opencensus-service/processor/piifilterprocessor"
	"go.uber.org/zap"
)

const (
	enduserIDAttribute      = "enduser.id"
	enduserRoleAttribute    = "enduser.role"
	enduserScopeAttribute   = "enduser.scope"
	enduserSessionAttribute = "session.id"
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
	Key             string      `mapstructure:"key"`
	Type            string      `mapstructure:"type"`
	Encoding        string      `mapstructure:"encoding"`
	CookieName      string      `mapstructure:"cookie_name"`
	RawSessionValue bool        `mapstructure:"raw_session_value"`
	Conditions      []Condition `mapstructure:"conditions"`
	IDClaims        []string    `mapstructure:"id_claims"`
	IDPaths         []string    `mapstructure:"id_paths"`
	IDKeys          []string    `mapstructure:"id_keys"`
	RoleClaims      []string    `mapstructure:"role_claims"`
	RolePaths       []string    `mapstructure:"role_paths"`
	RoleKeys        []string    `mapstructure:"role_keys"`
	ScopeClaims     []string    `mapstructure:"scope_claims"`
	ScopePaths      []string    `mapstructure:"scope_paths"`
	ScopeKeys       []string    `mapstructure:"scope_keys"`
	SessionClaims   []string    `mapstructure:"session_claims"`
	SessionPaths    []string    `mapstructure:"session_paths"`
	SessionKeys     []string    `mapstructure:"session_keys"`
}

type enduserprocessor struct {
	nextConsumer consumer.TraceConsumer
	logger       *zap.Logger
	endusers     []Enduser
	enduserMap   map[string][]Enduser
}

// NewTraceProcessor creates a new end user processor which adds enduser attributes to spans when
// data is available
func NewTraceProcessor(nextConsumer consumer.TraceConsumer, endusers []Enduser, logger *zap.Logger) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, errors.New("nextConsumer is nil")
	}
	enduserMap := make(map[string][]Enduser)
	for _, enduser := range endusers {
		enduserMap[enduser.Key] = append(enduserMap[enduser.Key], enduser)
	}

	return &enduserprocessor{
		nextConsumer: nextConsumer,
		logger:       logger,
		endusers:     endusers,
		enduserMap:   enduserMap,
	}, nil
}

func (processor *enduserprocessor) ConsumeTraceData(ctx context.Context, td data.TraceData) error {
	for _, span := range td.Spans {
		if span == nil || span.Attributes == nil {
			continue
		}
		attribMap := span.Attributes.AttributeMap
		if len(attribMap) == 0 {
			continue
		}

		// iterate through enduer locations and see if
		// the keys exist in the span
		for key, attrib := range attribMap {
			value := attrib.GetStringValue()
			if value == nil {
				continue
			}
			unindexedKey := piifilterprocessor.UnindexedKey(key)
			if endusers, ok := processor.enduserMap[unindexedKey]; ok {
				for _, enduser := range endusers {
					processor.capture(span, enduser, value.Value)
				}
			}
		}
	}

	return processor.nextConsumer.ConsumeTraceData(ctx, td)
}

type user struct {
	id      string
	role    string
	scope   string
	session string
}

func (processor *enduserprocessor) capture(span *tracepb.Span, enduser Enduser, value string) {
	if !processor.passesConditions(span, enduser.Conditions) {
		return
	}

	var user *user
	switch enduser.Type {
	case "authheader":
		user = processor.authHeaderCapture(enduser, value)
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

	if len(user.session) > 0 {
		addSpanAttribute(span, enduserSessionAttribute, user.session)
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

func (processor *enduserprocessor) authHeaderCapture(enduser Enduser, value string) *user {
	lcValue := strings.ToLower(value)
	if strings.HasPrefix(lcValue, "bearer ") {
		tokenString := value[7:]
		var user *user
		switch enduser.Encoding {
		case "jwt":
			user = processor.decodeJwt(enduser, tokenString)
			if len(user.session) == 0 {
				user.session = piifilterprocessor.HashValue(tokenString)
			}
		default:
			processor.logger.Info("Unknown auth header encoding", zap.String("value", enduser.Encoding))
			return nil
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
		processor.logger.Info("Authorization header must be basic or bearer", zap.String("value", value))
	}

	return nil
}

func (processor *enduserprocessor) decodeJwt(enduser Enduser, tokenString string) *user {
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
	for _, claim := range enduser.SessionClaims {
		if session, ok := claims[claim]; ok {
			user.session = processor.jsonToString(session)
			if !enduser.RawSessionValue {
				user.session = piifilterprocessor.HashValue(user.session)
			}
			break
		}
	}
	return user
}

func (processor *enduserprocessor) jsonToString(value interface{}) string {
	// only unmarshal the value if it's a complex type, as we don't
	// want all string values to be quoted
	valueString, ok := value.(string)
	if ok {
		return valueString
	}

	json, err := json.Marshal(value)
	if err != nil {
		processor.logger.Info("invalid json value", zap.Error(err))
		return ""
	}

	return string(json)
}

func (processor *enduserprocessor) jsonCapture(enduser Enduser, value string) *user {
	var v interface{}
	err := jsoniter.Config{
		EscapeHTML:              false,
		MarshalFloatWith6Digits: false,
		ValidateJsonRawMessage:  false,
	}.Froze().UnmarshalFromString(value, &v)
	// if there's an error parsing the json, log it for debuggin, but carry on
	// as we can usually still extract the user info from truncated json.
	if err != nil {
		processor.logger.Debug("Could not parse json to capture user", zap.Error(err))
	}

	user := new(user)
	for _, path := range enduser.IDPaths {
		id, err := jsonpath.Get(path, v)
		if err == nil {
			user.id = processor.jsonToString(id)
			break
		}
	}
	for _, path := range enduser.RolePaths {
		role, err := jsonpath.Get(path, v)
		if err == nil {
			user.role = processor.jsonToString(role)
			break
		}
	}
	for _, path := range enduser.ScopePaths {
		scope, err := jsonpath.Get(path, v)
		if err == nil {
			user.scope = processor.jsonToString(scope)
			break
		}
	}
	for _, path := range enduser.SessionPaths {
		session, err := jsonpath.Get(path, v)
		if err == nil {
			user.session = processor.jsonToString(session)
			if !enduser.RawSessionValue {
				user.session = piifilterprocessor.HashValue(user.session)
			}
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
	for _, key := range enduser.SessionKeys {
		if values, ok := params[key]; ok {
			for _, value := range values {
				if len(value) > 0 {
					user.session = value
					if !enduser.RawSessionValue {
						user.session = piifilterprocessor.HashValue(user.session)
					}
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

	if len(enduser.Encoding) > 0 {
		switch enduser.Encoding {
		case "jwt":
			if len(enduser.CookieName) > 0 {
				for _, cookie := range cookies {
					if cookie.Name == enduser.CookieName {
						user := processor.decodeJwt(enduser, cookie.Value)
						if user == nil {
							return nil
						}
						// use the jwt cookie as the session string
						if len(user.session) == 0 {
							user.session = piifilterprocessor.HashValue(cookie.Value)
						}
						return user
					}
				}
			} else {
				processor.logger.Info("cookie_name must be specified when using jwt encoding")
				return nil
			}
		default:
			processor.logger.Info("Unknown cookie encoding", zap.String("value", enduser.Encoding))
			return nil
		}
	}

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
	for _, key := range enduser.SessionKeys {
		for _, cookie := range cookies {
			if cookie.Name == key {
				user.session = cookie.Value
				if !enduser.RawSessionValue {
					user.session = piifilterprocessor.HashValue(user.session)
				}
				break
			}
		}
		if len(user.scope) > 0 {
			break
		}
	}

	return user
}
