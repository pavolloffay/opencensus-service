package decoder

import (
	"math"
	"strconv"

	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protowire"
)

// Taken from protowire package.
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

// NewProtoDecoder returns a new protodecoder object which can be used for decoding
// protobufs messages. The decoding of protobuf is based on the proto wire format
// defined here: https://developers.google.com/protocol-buffers/docs/encoding.
// The strategy of protobuf decoding is similar to what we get when decoding is
// done using protoc --decode_raw
func NewProtoDecoder(logger *zap.Logger) *Protodecoder {
	return &Protodecoder{
		logger: logger,
	}
}

// Decode when called on bytes returns an object which follows the
// proto message hierarchy closely. Field identifiers are converted
// to string keys and values are associatd to these keys
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

		if consumed > len(pending) {
			return nil, errCodeTruncated
		}
		pending = pending[consumed:]
		parsed += consumed
	}
	return out, parsed
}

// updateMap updates the key value map. If a key is already present in the map, then if the
// associatd value is a list, we append the new value to the list. If the existing value is
// not a list then a list is created and values are added to the new list.
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

// decodeKeyVal deals with decoding of messages based on the type of message.
// Note: For decoding Fixed32 and Fixed64 type, default strategy is to decode
// to float32/64. In case decoding fails in such case, fallback to uint64
func (pd *Protodecoder) decodeKeyVal(b []byte) (protowire.Number, protowire.Type, interface{}, int) {
	num, tag, consumed := protowire.ConsumeTag(b)
	if consumed < 0 {
		return -1, tag, nil, consumed
	}
	if consumed > len(b) {
		return -1, tag, nil, errCodeTruncated
	}
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

			if n > len(val) {
				return -1, tag, nil, errCodeTruncated
			}
			val = val[n:]
		}
	case protowire.EndGroupType:
		return num, tag, nil, consumed
	default:
		return -1, tag, nil, errCodeFieldNumber
	}
}
