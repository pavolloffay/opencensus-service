package decoder

import (
	"math"
	"strconv"

	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protowire"
)

// TODO: Add error messages
const (
	_ = -iota
	errCodeTruncated
	errCodeFieldNumber
	errCodeOverflow
	errCodeReserved
	errCodeEndGroup
)

type Protodecoder struct {
	logger *zap.Logger
}

func NewProtoDecoder(logger *zap.Logger) *Protodecoder {
	return &Protodecoder{
		logger: logger,
	}
}

func (pd *Protodecoder) Decode(b []byte) (interface{}, int) {
	length := len(b)
	parsed := 0
	out := make(map[string]interface{})
	pending := b
	for {
		if parsed >= length {
			break
		}
		num, _, val, consumed := pd.decodeKeyVal(pending)
		if consumed < 0 {
			return nil, consumed
		}
		// Update map for array
		pd.updateMap(out, strconv.Itoa(int(num)), val)

		// TODO: Add consumed check for consumed value > len of pending
		pending = pending[consumed:]
		parsed += consumed
	}
	return out, parsed
}

func (pd *Protodecoder) updateMap(m map[string]interface{}, key string, val interface{}) {
	existing, ok := m[key]
	if !ok {
		m[key] = val
		return
	}

	switch tt := existing.(type) {
	case []interface{}:
		existing = append(tt, val)
		m[key] = existing
	case interface{}:
		newVal := make([]interface{}, 0)
		newVal = append(newVal, tt)
		newVal = append(newVal, val)
		m[key] = newVal
	}
	return
}

// TODO: Add reasoning for using float instead of unint
func (pd *Protodecoder) decodeKeyVal(b []byte) (protowire.Number, protowire.Type, interface{}, int) {
	num, tag, consumed := protowire.ConsumeTag(b)
	if consumed < 0 {
		return -1, tag, nil, consumed
	}
	// TODO: Add consumed check for consumed value > len of pending
	val := b[consumed:]

	switch tag {
	case protowire.VarintType:
		ret, n := protowire.ConsumeVarint(val)
		if n < 0 {
			return -1, tag, nil, n
		}
		consumed += n
		return num, tag, ret, consumed
	case protowire.Fixed32Type:
		ret, n := protowire.ConsumeFixed32(val)
		if n < 0 {
			return -1, tag, nil, n
		}
		consumed += n
		float32Rep := math.Float32frombits(ret)
		if math.IsNaN(float64(float32Rep)) {
			return num, tag, ret, consumed
		}
		return num, tag, math.Float32frombits(ret), consumed
	case protowire.Fixed64Type:
		ret, n := protowire.ConsumeFixed64(val)
		if n < 0 {
			return -1, tag, nil, n
		}
		consumed += n
		float64Rep := math.Float64frombits(ret)
		if math.IsNaN(float64Rep) {
			return num, tag, ret, consumed
		}
		return num, tag, math.Float64frombits(ret), consumed
	case protowire.BytesType:
		ret, n := protowire.ConsumeBytes(val)
		if n < 0 {
			return -1, tag, nil, n
		}
		out, y := pd.Decode(ret)
		if y == len(ret) {
			consumed += n
			return num, tag, out, consumed
		}
		str := string(ret)
		consumed += n
		return num, tag, str, consumed
	case protowire.StartGroupType:
		out := make(map[string]interface{})
		for {
			num2, tag2, ret, n := pd.decodeKeyVal(val)
			if n < 0 {
				return -1, tag, nil, n
			}
			consumed += n
			if tag2 == protowire.EndGroupType {
				if num != num2 {
					return -1, tag, nil, errCodeEndGroup
				}
				return num, tag, out, consumed
			} else {
				pd.updateMap(out, strconv.Itoa(int(num2)), ret)
			}
			// TODO: Add consumed check for consumed value > len of pending
			val = val[n:]
		}
	case protowire.EndGroupType:
		return num, tag, nil, consumed
	default:
		return -1, tag, nil, errCodeFieldNumber
	}
}
