package decoder

import (
	"encoding/hex"
	"fmt"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_grpcdecoder(t *testing.T) {
	encodedUnaryMessage := "000000004f0a3a4265726b73686972652056616c6c6579204d616e6167656d656e7420417265612054" +
		"7261696c2c204a6566666572736f6e2c204e4a2c205553411211089aa68cc30110969f989cfdffffffff01"
	decodedUnaryMessageJson := `{"1":"Berkshire Valley Management Area Trail, Jefferson, NJ, USA","2":{"1":409146138,"2":18446744072963362710}}`

	encodedStreamMessage := "000000003a0a2550617472696f747320506174682c204d656e6468616d2c204e4a2030373934352c205553" +
		"411211088fbdbcc20110edff9a9cfdffffffff01000000003f0a2a313031204e6577204a65727365792031302c205768697070616e792c2" +
		"04e4a2030373938312c20555341121108b8ebcdc20110b5f29d9dfdffffffff0100000000330a1e552e532e20362c2053686f686f6c612c" +
		"2050412031383435382c20555341121108fced9dc50110d4dceb9afdffffffff01000000003c0a273520436f6e6e65727320526f61642c204" +
		"b696e6773746f6e2c204e592031323430312c20555341121108b8dea2c80110c0aafb9efdffffffff01"
	decodedStreamMessageJson := `[{"1":"Patriots Path, Mendham, NJ 07945, USA","2":{"1":407838351,"2":18446744072963407853}},` +
		`{"1":"101 New Jersey 10, Whippany, NJ 07981, USA","2":{"1":408122808,"2":18446744072965552437}},` +
		`{"1":"U.S. 6, Shohola, PA 18458, USA","2":{"1":413628156,"2":18446744072960536148}},` +
		`{"1":"5 Conners Road, Kingston, NY 12401, USA","2":{"1":419999544,"2":18446744072969180480}}]`

	tests := []struct {
		name          string
		serialized    string
		wantJson      string
		errorExpected bool
		errorCode     int
	}{
		{
			name:       "check_unary_message",
			serialized: encodedUnaryMessage,
			wantJson:   decodedUnaryMessageJson,
		},
		{
			name:       "check_stream_message",
			serialized: encodedStreamMessage,
			wantJson:   decodedStreamMessageJson,
		},
	}
	logger := zap.New(zapcore.NewNopCore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gomega.RegisterTestingT(t)
			matcher := gomega.MatchJSON(tt.wantJson)
			decoder := NewGrpcDecoder(logger)

			var serialized []byte
			var err error

			serialized, err = hex.DecodeString(tt.serialized)
			if err != nil {
				t.Errorf("Error while getting serialized bytes: %v", err)
				return
			}

			out, consumed := decoder.Decode(serialized)

			messageLen := len(serialized)
			if tt.errorExpected {
				gomega.Expect(consumed == tt.errorCode).Should(gomega.BeTrue(), fmt.Sprintf("Expected error: %v. Got %v", tt.errorCode, consumed))
			} else {
				gomega.Expect(consumed == messageLen).Should(gomega.BeTrue(), fmt.Sprintf("Expected consumed: %v. Got %v", messageLen, consumed))
			}

			outJson, err := jsoniter.MarshalToString(out)
			if err != nil {
				t.Errorf("Error while marshaling to json: %v", err)
				return
			}
			success, err := matcher.Match(outJson)
			gomega.Expect(err).Should(gomega.BeNil())
			gomega.Expect(success).Should(gomega.BeTrue(), fmt.Sprintf("Expected json match: %v. Got %v", tt.wantJson, outJson))
		})
	}
}
