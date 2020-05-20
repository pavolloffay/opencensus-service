package piifilterprocessor

import (
	"bytes"
	"encoding/json"
	"strings"
)

type RedactionStrategy int

const (
	Dummy RedactionStrategy = iota
	Redact
	Hash
)

var toString = map[RedactionStrategy]string{
	Redact: "redact",
	Hash:   "hash",
}

var fromString = map[string]RedactionStrategy{
	"redact": Redact,
	"hash":   Hash,
}

func (rs RedactionStrategy) String() string {
	return toString[rs]
}

func toId(str string) RedactionStrategy {
	return fromString[strings.ToLower(str)]
}

// MarshalJSON marshals the enum as a quoted json string
func (s RedactionStrategy) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (s *RedactionStrategy) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	*s = toId(j)
	return nil
}
