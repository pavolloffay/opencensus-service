package decoder

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	pb "github.com/census-instrumentation/opencensus-service/processor/protoprocessor/decoder/internal"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

func Test_decoder_coverage(t *testing.T) {
	logger := zap.New(zapcore.NewNopCore())
	decoder := NewProtoDecoder(logger)
	p := pb.Person{
		Id:    1234,
		Name:  "John Doe",
		Email: "jdoe@example.com",
		Phones: []*pb.Person_PhoneNumber{
			{Number: "555-4321", Type: pb.Person_HOME},
		},
	}
	message := &pb.AddressBook{}
	message.Id = 3030
	message.Val = append(message.Val, 1122)
	message.Val = append(message.Val, 2233)
	message.Val = append(message.Val, 3344)
	message.People = append(message.People, &p)
	serialized, err := proto.Marshal(message)
	if err != nil {
		fmt.Println("Error while serializing the message")
	}

	fmt.Println(hex.EncodeToString(serialized))

	// fmt.Println(DecodeKeyVal(serialized))
	x, _ := decoder.Decode(serialized)
	empData, err := json.Marshal(x)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	jsonStr := string(empData)
	fmt.Println("The JSON data is:")
	fmt.Println(jsonStr)

	str, err := jsoniter.MarshalToString(x)
	if err != nil {
		fmt.Println("Error while creating json")
	}

	fmt.Println(str)

}
