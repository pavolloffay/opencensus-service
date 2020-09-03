package decoder

import (
	"encoding/hex"
	"fmt"
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/processor/protoprocessor/decoder/internal"
	jsoniter "github.com/json-iterator/go"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

func Test_protodecoder_coverage(t *testing.T) {
	strArr := &pb.Coverage{}
	strArr.VarString = append(strArr.VarString, "string1")
	strArr.VarString = append(strArr.VarString, "string2")
	strArr.VarString = append(strArr.VarString, "string3")
	strArr.VarString = append(strArr.VarString, "string4")

	p := pb.Person{
		Id:    1234,
		Name:  "John Doe",
		Email: "jdoe@example.com",
		Phones: []*pb.Person_PhoneNumber{
			{Number: "555-4321", Type: pb.Person_HOME},
			{Number: "111-7890", Type: pb.Person_WORK},
		},
	}
	addressBook := &pb.AddressBook{}
	addressBook.Id = 3030
	addressBook.Val = append(addressBook.Val, 1122)
	addressBook.Val = append(addressBook.Val, 2233)
	addressBook.Val = append(addressBook.Val, 3344)
	addressBook.StringVals = append(addressBook.StringVals, "string1")
	addressBook.StringVals = append(addressBook.StringVals, "string2")
	addressBook.StringVals = append(addressBook.StringVals, "string3")
	addressBook.StringVals = append(addressBook.StringVals, "string4")
	addressBook.People = append(addressBook.People, &p)
	addressBook.People = append(addressBook.People, &p)
	addressBook.People = append(addressBook.People, &p)

	encodedGroup := "0bb301eb14e39502e49502ec14b4010cc3b80208959aef3a6515cd5b07d90715cd5b0700000000" +
		"924d0568656c6c6fcb830658959aef3ae54b15cd5b07998f3c15cd5b070000000092ff892f07676f6f64627965cc8306c4b802"
	addressBookDecodedJson := `{"17":["string1","string2","string3","string4"],` +
		`"20":[{"33":"John Doe","44":1234,"55":"jdoe@example.com","66":[{"1":"555-4321","2":1},{"1":"111-7890","2":2}]},` +
		`{"33":"John Doe","44":1234,"55":"jdoe@example.com","66":[{"1":"555-4321","2":1},{"1":"111-7890","2":2}]},` +
		`{"44":1234,"55":"jdoe@example.com","66":[{"1":"555-4321","2":1},{"2":2,"1":"111-7890"}],"33":"John Doe"}],` +
		`"10":3030,"15":"\ufffd\u0008\ufffd\u0011\ufffd\u001a"}`
	groupDecodedJson := `{"1":{"22":{"333":{"4444":{}}}},` +
		`"5000":{"1":123456789,"12":1.6535997e-34,"123":6.0995758e-316,"1234":"hello",` +
		`"12345":{"11":123456789,"1212":1.6535997e-34,"123123":6.0995758e-316,"12341234":"goodbye"}}}`

	tests := []struct {
		name          string
		message       proto.Message
		serialized    string
		wantJson      string
		errorExpected bool
		errorCode     int
	}{
		{
			name: "check_int32",
			message: &pb.Coverage{
				VarInt32: 3040,
			},
			wantJson: `{"11":3040}`,
		},
		{
			name: "check_negative_int32",
			message: &pb.Coverage{
				VarInt32: -3040,
			},
			wantJson: `{"11":18446744073709548576}`,
		},
		{
			name: "check_int64",
			message: &pb.Coverage{
				VarInt64: 3040,
			},
			wantJson: `{"22":3040}`,
		},
		{
			name: "check_negative_int64",
			message: &pb.Coverage{
				VarInt64: -3040,
			},
			wantJson: `{"22":18446744073709548576}`,
		},
		{
			name: "check_uint32",
			message: &pb.Coverage{
				VarUint32: 3040,
			},
			wantJson: `{"33":3040}`,
		},
		{
			name: "check_uint64",
			message: &pb.Coverage{
				VarUint64: 3040,
			},
			wantJson: `{"44":3040}`,
		},
		{
			name: "check_sint32",
			message: &pb.Coverage{
				VarSint32: 3040,
			},
			wantJson: `{"55":6080}`,
		},
		{
			name: "check_negative_sint32",
			message: &pb.Coverage{
				VarSint32: -3040,
			},
			wantJson: `{"55":6079}`,
		},
		{
			name: "check_sint64",
			message: &pb.Coverage{
				VarSint64: 3040,
			},
			wantJson: `{"66":6080}`,
		},
		{
			name: "check_negative_sint64",
			message: &pb.Coverage{
				VarSint64: -3040,
			},
			wantJson: `{"66":6079}`,
		},
		{
			name: "check_bool_true",
			message: &pb.Coverage{
				VarBool: true,
			},
			wantJson: `{"77":1}`,
		},
		{
			name: "check_bool_false",
			message: &pb.Coverage{
				VarBool: false,
			},
			// Protobuf doesn't encode the default bool in the message
			wantJson: `{}`,
		},
		{
			name: "check_enum_enum1",
			message: &pb.Coverage{
				VarEnum: pb.Coverage_ENUM1,
			},
			// Protobuf doesn't encode the default enum in the message
			wantJson: `{}`,
		},
		{
			name: "check_enum_enum2",
			message: &pb.Coverage{
				VarEnum: pb.Coverage_ENUM2,
			},
			wantJson: `{"88":1}`,
		},
		{
			name: "check_enum_enum3",
			message: &pb.Coverage{
				VarEnum: pb.Coverage_ENUM3,
			},
			wantJson: `{"88":100}`,
		},
		{
			name: "check_fixed64",
			message: &pb.Coverage{
				VarFixed64: 3040,
			},
			wantJson: `{"99":1.502e-320}`,
		},
		{
			name: "check_sfixed64",
			message: &pb.Coverage{
				VarSfixed64: 3040,
			},
			wantJson: `{"1010":1.502e-320}`,
		},
		{
			name: "check_negative_sfixed64",
			message: &pb.Coverage{
				VarSfixed64: -3040,
			},
			wantJson: `{"1010":18446744073709548576}`,
		},
		{
			name: "check_double",
			message: &pb.Coverage{
				VarDouble: 3040.123,
			},
			wantJson: `{"1111":3040.123}`,
		},
		{
			name: "check_negative_double",
			message: &pb.Coverage{
				VarDouble: -3040.789,
			},
			wantJson: `{"1111":-3040.789}`,
		},
		{
			name: "check_fixed32",
			message: &pb.Coverage{
				VarFixed32: 3040,
			},
			wantJson: `{"1212":4.26e-42}`,
		},
		{
			name: "check_sfixed32",
			message: &pb.Coverage{
				VarSfixed32: 3040,
			},
			wantJson: `{"1313":4.26e-42}`,
		},
		{
			name: "check_negative_sfixed32",
			message: &pb.Coverage{
				VarSfixed32: -3040,
			},
			wantJson: `{"1313":4294964256}`,
		},
		{
			name: "check_float",
			message: &pb.Coverage{
				VarFloat: 3040.234,
			},
			wantJson: `{"1414":3040.234}`,
		},
		{
			name: "check_negative_float",
			message: &pb.Coverage{
				VarFloat: -3040.567,
			},
			wantJson: `{"1414":-3040.567}`,
		},
		{
			name:     "check_strarr",
			message:  strArr,
			wantJson: `{"1515":["string1","string2","string3","string4"]}`,
		},
		{
			name:     "check_addressbook",
			message:  addressBook,
			wantJson: addressBookDecodedJson,
		},
		{
			name:       "check_group",
			serialized: encodedGroup,
			wantJson:   groupDecodedJson,
		},
	}
	logger := zap.New(zapcore.NewNopCore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gomega.RegisterTestingT(t)
			matcher := gomega.MatchJSON(tt.wantJson)
			decoder := NewProtoDecoder(logger)

			var serialized []byte
			var err error

			if (len(tt.serialized)) != 0 {
				serialized, err = hex.DecodeString(tt.serialized)
				if err != nil {
					t.Errorf("Error while getting serialized bytes: %v", err)
					return
				}
			} else {
				serialized, err = proto.Marshal(tt.message)
				if err != nil {
					t.Errorf("Error while serializing the message: %v", err)
					return
				}
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
