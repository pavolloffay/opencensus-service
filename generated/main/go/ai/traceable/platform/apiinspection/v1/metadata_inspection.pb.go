// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.11.4
// source: ai/traceable/platform/apiinspection/v1/metadata_inspection.proto

package ai_traceable_platform_apiinspection_v1

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// Param Value Metadata
type ParamValueType int32

const (
	ParamValueType_PARAM_VALUE_TYPE_UNSPECIFIED ParamValueType = 0
	ParamValueType_PARAM_VALUE_TYPE_BOOLEAN     ParamValueType = 1
	ParamValueType_PARAM_VALUE_TYPE_INTEGER     ParamValueType = 2
	ParamValueType_PARAM_VALUE_TYPE_FLOAT       ParamValueType = 3
	ParamValueType_PARAM_VALUE_TYPE_CHAR        ParamValueType = 4
	ParamValueType_PARAM_VALUE_TYPE_STRING      ParamValueType = 5
	ParamValueType_PARAM_VALUE_TYPE_URL         ParamValueType = 6
	ParamValueType_PARAM_VALUE_TYPE_EMAIL       ParamValueType = 7
	ParamValueType_PARAM_VALUE_TYPE_JSON        ParamValueType = 8
	ParamValueType_PARAM_VALUE_TYPE_CREDIT_CARD ParamValueType = 9
	ParamValueType_PARAM_VALUE_TYPE_DATE        ParamValueType = 10
)

// Enum value maps for ParamValueType.
var (
	ParamValueType_name = map[int32]string{
		0:  "PARAM_VALUE_TYPE_UNSPECIFIED",
		1:  "PARAM_VALUE_TYPE_BOOLEAN",
		2:  "PARAM_VALUE_TYPE_INTEGER",
		3:  "PARAM_VALUE_TYPE_FLOAT",
		4:  "PARAM_VALUE_TYPE_CHAR",
		5:  "PARAM_VALUE_TYPE_STRING",
		6:  "PARAM_VALUE_TYPE_URL",
		7:  "PARAM_VALUE_TYPE_EMAIL",
		8:  "PARAM_VALUE_TYPE_JSON",
		9:  "PARAM_VALUE_TYPE_CREDIT_CARD",
		10: "PARAM_VALUE_TYPE_DATE",
	}
	ParamValueType_value = map[string]int32{
		"PARAM_VALUE_TYPE_UNSPECIFIED": 0,
		"PARAM_VALUE_TYPE_BOOLEAN":     1,
		"PARAM_VALUE_TYPE_INTEGER":     2,
		"PARAM_VALUE_TYPE_FLOAT":       3,
		"PARAM_VALUE_TYPE_CHAR":        4,
		"PARAM_VALUE_TYPE_STRING":      5,
		"PARAM_VALUE_TYPE_URL":         6,
		"PARAM_VALUE_TYPE_EMAIL":       7,
		"PARAM_VALUE_TYPE_JSON":        8,
		"PARAM_VALUE_TYPE_CREDIT_CARD": 9,
		"PARAM_VALUE_TYPE_DATE":        10,
	}
)

func (x ParamValueType) Enum() *ParamValueType {
	p := new(ParamValueType)
	*p = x
	return p
}

func (x ParamValueType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ParamValueType) Descriptor() protoreflect.EnumDescriptor {
	return file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_enumTypes[0].Descriptor()
}

func (ParamValueType) Type() protoreflect.EnumType {
	return &file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_enumTypes[0]
}

func (x ParamValueType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ParamValueType.Descriptor instead.
func (ParamValueType) EnumDescriptor() ([]byte, []int) {
	return file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescGZIP(), []int{0}
}

// Special Character Inspection
type SpecialCharacterInspection struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StartsWithPipe  bool `protobuf:"varint,1,opt,name=starts_with_pipe,json=startsWithPipe,proto3" json:"starts_with_pipe,omitempty"`
	ContainsNosqlOp bool `protobuf:"varint,2,opt,name=contains_nosql_op,json=containsNosqlOp,proto3" json:"contains_nosql_op,omitempty"`
	// Key: ASCII code of special char
	// Value: Number of occurrences
	SpecialCharDistribution map[int32]int32 `protobuf:"bytes,3,rep,name=special_char_distribution,json=specialCharDistribution,proto3" json:"special_char_distribution,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
}

func (x *SpecialCharacterInspection) Reset() {
	*x = SpecialCharacterInspection{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SpecialCharacterInspection) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SpecialCharacterInspection) ProtoMessage() {}

func (x *SpecialCharacterInspection) ProtoReflect() protoreflect.Message {
	mi := &file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SpecialCharacterInspection.ProtoReflect.Descriptor instead.
func (*SpecialCharacterInspection) Descriptor() ([]byte, []int) {
	return file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescGZIP(), []int{0}
}

func (x *SpecialCharacterInspection) GetStartsWithPipe() bool {
	if x != nil {
		return x.StartsWithPipe
	}
	return false
}

func (x *SpecialCharacterInspection) GetContainsNosqlOp() bool {
	if x != nil {
		return x.ContainsNosqlOp
	}
	return false
}

func (x *SpecialCharacterInspection) GetSpecialCharDistribution() map[int32]int32 {
	if x != nil {
		return x.SpecialCharDistribution
	}
	return nil
}

// Metadata inspection for a single value
type MetadataInspection struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value                 *Value                      `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Type                  ParamValueType              `protobuf:"varint,2,opt,name=type,proto3,enum=ai.traceable.platform.apiinspection.v1.ParamValueType" json:"type,omitempty"`
	Length                int32                       `protobuf:"varint,3,opt,name=length,proto3" json:"length,omitempty"`
	SpecialCharInspection *SpecialCharacterInspection `protobuf:"bytes,4,opt,name=special_char_inspection,json=specialCharInspection,proto3" json:"special_char_inspection,omitempty"`
}

func (x *MetadataInspection) Reset() {
	*x = MetadataInspection{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetadataInspection) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetadataInspection) ProtoMessage() {}

func (x *MetadataInspection) ProtoReflect() protoreflect.Message {
	mi := &file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetadataInspection.ProtoReflect.Descriptor instead.
func (*MetadataInspection) Descriptor() ([]byte, []int) {
	return file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescGZIP(), []int{1}
}

func (x *MetadataInspection) GetValue() *Value {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *MetadataInspection) GetType() ParamValueType {
	if x != nil {
		return x.Type
	}
	return ParamValueType_PARAM_VALUE_TYPE_UNSPECIFIED
}

func (x *MetadataInspection) GetLength() int32 {
	if x != nil {
		return x.Length
	}
	return 0
}

func (x *MetadataInspection) GetSpecialCharInspection() *SpecialCharacterInspection {
	if x != nil {
		return x.SpecialCharInspection
	}
	return nil
}

var File_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto protoreflect.FileDescriptor

var file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDesc = []byte{
	0x0a, 0x40, 0x61, 0x69, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x70,
	0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73, 0x70, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x5f, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x26, 0x61, 0x69, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65,
	0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73,
	0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x1a, 0x3b, 0x61, 0x69, 0x2f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72,
	0x6d, 0x2f, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f,
	0x76, 0x31, 0x2f, 0x65, 0x6e, 0x75, 0x6d, 0x5f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x32, 0x61, 0x69, 0x2f, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x61,
	0x70, 0x69, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xdc, 0x02, 0x0a, 0x1a,
	0x53, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x43, 0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65, 0x72,
	0x49, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x28, 0x0a, 0x10, 0x73, 0x74,
	0x61, 0x72, 0x74, 0x73, 0x5f, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x70, 0x69, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x73, 0x74, 0x61, 0x72, 0x74, 0x73, 0x57, 0x69, 0x74, 0x68,
	0x50, 0x69, 0x70, 0x65, 0x12, 0x2a, 0x0a, 0x11, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73,
	0x5f, 0x6e, 0x6f, 0x73, 0x71, 0x6c, 0x5f, 0x6f, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x4e, 0x6f, 0x73, 0x71, 0x6c, 0x4f, 0x70,
	0x12, 0x9b, 0x01, 0x0a, 0x19, 0x73, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x5f, 0x63, 0x68, 0x61,
	0x72, 0x5f, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x5f, 0x2e, 0x61, 0x69, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61,
	0x62, 0x6c, 0x65, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69,
	0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x70,
	0x65, 0x63, 0x69, 0x61, 0x6c, 0x43, 0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65, 0x72, 0x49, 0x6e,
	0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x53, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c,
	0x43, 0x68, 0x61, 0x72, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x17, 0x73, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x43, 0x68,
	0x61, 0x72, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x4a,
	0x0a, 0x1c, 0x53, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x43, 0x68, 0x61, 0x72, 0x44, 0x69, 0x73,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xb9, 0x02, 0x0a, 0x12, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x49, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x43, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2d, 0x2e, 0x61, 0x69, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65, 0x2e,
	0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73, 0x70,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x4a, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x36, 0x2e, 0x61, 0x69, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61,
	0x62, 0x6c, 0x65, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69,
	0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x61,
	0x72, 0x61, 0x6d, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x12, 0x7a, 0x0a, 0x17, 0x73, 0x70,
	0x65, 0x63, 0x69, 0x61, 0x6c, 0x5f, 0x63, 0x68, 0x61, 0x72, 0x5f, 0x69, 0x6e, 0x73, 0x70, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x42, 0x2e, 0x61, 0x69,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66,
	0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x43, 0x68, 0x61, 0x72,
	0x61, 0x63, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x15, 0x73, 0x70, 0x65, 0x63, 0x69, 0x61, 0x6c, 0x43, 0x68, 0x61, 0x72, 0x49, 0x6e, 0x73, 0x70,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2a, 0xd5, 0x03, 0x0a, 0x0e, 0x50, 0x61, 0x72, 0x61, 0x6d,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x31, 0x0a, 0x1c, 0x50, 0x41, 0x52,
	0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e,
	0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x1a, 0x0f, 0x82, 0xb5, 0x18,
	0x0b, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x12, 0x29, 0x0a, 0x18,
	0x50, 0x41, 0x52, 0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45,
	0x5f, 0x42, 0x4f, 0x4f, 0x4c, 0x45, 0x41, 0x4e, 0x10, 0x01, 0x1a, 0x0b, 0x82, 0xb5, 0x18, 0x07,
	0x42, 0x4f, 0x4f, 0x4c, 0x45, 0x41, 0x4e, 0x12, 0x29, 0x0a, 0x18, 0x50, 0x41, 0x52, 0x41, 0x4d,
	0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x4e, 0x54, 0x45,
	0x47, 0x45, 0x52, 0x10, 0x02, 0x1a, 0x0b, 0x82, 0xb5, 0x18, 0x07, 0x49, 0x4e, 0x54, 0x45, 0x47,
	0x45, 0x52, 0x12, 0x25, 0x0a, 0x16, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55,
	0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x46, 0x4c, 0x4f, 0x41, 0x54, 0x10, 0x03, 0x1a, 0x09,
	0x82, 0xb5, 0x18, 0x05, 0x46, 0x4c, 0x4f, 0x41, 0x54, 0x12, 0x23, 0x0a, 0x15, 0x50, 0x41, 0x52,
	0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x43, 0x48,
	0x41, 0x52, 0x10, 0x04, 0x1a, 0x08, 0x82, 0xb5, 0x18, 0x04, 0x43, 0x48, 0x41, 0x52, 0x12, 0x27,
	0x0a, 0x17, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59,
	0x50, 0x45, 0x5f, 0x53, 0x54, 0x52, 0x49, 0x4e, 0x47, 0x10, 0x05, 0x1a, 0x0a, 0x82, 0xb5, 0x18,
	0x06, 0x53, 0x54, 0x52, 0x49, 0x4e, 0x47, 0x12, 0x21, 0x0a, 0x14, 0x50, 0x41, 0x52, 0x41, 0x4d,
	0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x52, 0x4c, 0x10,
	0x06, 0x1a, 0x07, 0x82, 0xb5, 0x18, 0x03, 0x55, 0x52, 0x4c, 0x12, 0x25, 0x0a, 0x16, 0x50, 0x41,
	0x52, 0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x45,
	0x4d, 0x41, 0x49, 0x4c, 0x10, 0x07, 0x1a, 0x09, 0x82, 0xb5, 0x18, 0x05, 0x45, 0x4d, 0x41, 0x49,
	0x4c, 0x12, 0x23, 0x0a, 0x15, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45,
	0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4a, 0x53, 0x4f, 0x4e, 0x10, 0x08, 0x1a, 0x08, 0x82, 0xb5,
	0x18, 0x04, 0x4a, 0x53, 0x4f, 0x4e, 0x12, 0x31, 0x0a, 0x1c, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x5f,
	0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x43, 0x52, 0x45, 0x44, 0x49,
	0x54, 0x5f, 0x43, 0x41, 0x52, 0x44, 0x10, 0x09, 0x1a, 0x0f, 0x82, 0xb5, 0x18, 0x0b, 0x43, 0x52,
	0x45, 0x44, 0x49, 0x54, 0x5f, 0x43, 0x41, 0x52, 0x44, 0x12, 0x23, 0x0a, 0x15, 0x50, 0x41, 0x52,
	0x41, 0x4d, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x41,
	0x54, 0x45, 0x10, 0x0a, 0x1a, 0x08, 0x82, 0xb5, 0x18, 0x04, 0x44, 0x41, 0x54, 0x45, 0x42, 0x02,
	0x50, 0x01, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescOnce sync.Once
	file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescData = file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDesc
)

func file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescGZIP() []byte {
	file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescOnce.Do(func() {
		file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescData = protoimpl.X.CompressGZIP(file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescData)
	})
	return file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDescData
}

var file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_goTypes = []interface{}{
	(ParamValueType)(0),                // 0: ai.traceable.platform.apiinspection.v1.ParamValueType
	(*SpecialCharacterInspection)(nil), // 1: ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection
	(*MetadataInspection)(nil),         // 2: ai.traceable.platform.apiinspection.v1.MetadataInspection
	nil,                                // 3: ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection.SpecialCharDistributionEntry
	(*Value)(nil),                      // 4: ai.traceable.platform.apiinspection.v1.Value
}
var file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_depIdxs = []int32{
	3, // 0: ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection.special_char_distribution:type_name -> ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection.SpecialCharDistributionEntry
	4, // 1: ai.traceable.platform.apiinspection.v1.MetadataInspection.value:type_name -> ai.traceable.platform.apiinspection.v1.Value
	0, // 2: ai.traceable.platform.apiinspection.v1.MetadataInspection.type:type_name -> ai.traceable.platform.apiinspection.v1.ParamValueType
	1, // 3: ai.traceable.platform.apiinspection.v1.MetadataInspection.special_char_inspection:type_name -> ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_init() }
func file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_init() {
	if File_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto != nil {
		return
	}
	file_ai_traceable_platform_apiinspection_v1_enum_extension_proto_init()
	file_ai_traceable_platform_apiinspection_v1_value_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SpecialCharacterInspection); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetadataInspection); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_goTypes,
		DependencyIndexes: file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_depIdxs,
		EnumInfos:         file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_enumTypes,
		MessageInfos:      file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_msgTypes,
	}.Build()
	File_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto = out.File
	file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_rawDesc = nil
	file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_goTypes = nil
	file_ai_traceable_platform_apiinspection_v1_metadata_inspection_proto_depIdxs = nil
}
