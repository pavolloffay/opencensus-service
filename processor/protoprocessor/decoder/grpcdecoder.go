package decoder

import (
	"encoding/binary"

	"go.uber.org/zap"
)

const (
	compressedByteIndex  = 0
	compressedByteCount  = 1
	lengthByteStartIndex = 1
	lengthByteCount      = 4
	messageStartIndex    = 5
	minimumByteCount     = compressedByteCount + lengthByteCount
)

type Grpcdecoder struct {
	logger       *zap.Logger
	protodecoder *Protodecoder
}

// NewGrpcDecoder returns a new grpcdecoder object which can be used for decoding
// grpcs messages. The decoding of grpc message is based on the message format
// defined here: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md.
func NewGrpcDecoder(logger *zap.Logger) *Grpcdecoder {
	protodecoder := NewProtoDecoder(logger)
	return &Grpcdecoder{
		logger:       logger,
		protodecoder: protodecoder,
	}
}

// Decode when called on bytes returns a messages or a list of messages
func (gd *Grpcdecoder) Decode(b []byte) (interface{}, int) {
	length := len(b)
	parsed := 0
	out := make([]interface{}, 0)
	pending := b
	parsedMessageCount := 0
	for {
		if parsed >= length {
			break
		}
		if len(pending) < minimumByteCount {
			if parsedMessageCount > 0 {
				return out, parsed
			} else {
				return nil, errCodeTruncated
			}
		}

		// TODO: Add support for decompression
		compressed := int(pending[compressedByteIndex])
		messageLen := int(binary.BigEndian.Uint32(pending[lengthByteStartIndex:messageStartIndex]))
		if messageLen > len(pending[messageStartIndex:]) {

			if parsedMessageCount > 0 {
				return out, parsed
			} else {
				return nil, errCodeTruncated
			}
		}
		sectionLen := minimumByteCount + messageLen
		message := pending[messageStartIndex:][:messageLen]

		if compressed == 0 {
			decoded, consumed := gd.protodecoder.Decode(message)
			if consumed >= 0 {
				out = append(out, decoded)
				parsedMessageCount += 1
			}
		}

		pending = pending[sectionLen:]
		parsed += sectionLen
	}
	if len(out) == 1 {
		return out[0], parsed
	}
	return out, parsed
}
