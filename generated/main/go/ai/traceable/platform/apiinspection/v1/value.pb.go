// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.11.4
// source: ai/traceable/platform/apiinspection/v1/value.proto

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

type ValueType int32

const (
	ValueType_VALUE_TYPE_UNSPECIFIED ValueType = 0
	ValueType_VALUE_TYPE_RAW         ValueType = 1
	ValueType_VALUE_TYPE_HASHED      ValueType = 2
	ValueType_VALUE_TYPE_REDACTED    ValueType = 3
)

// Enum value maps for ValueType.
var (
	ValueType_name = map[int32]string{
		0: "VALUE_TYPE_UNSPECIFIED",
		1: "VALUE_TYPE_RAW",
		2: "VALUE_TYPE_HASHED",
		3: "VALUE_TYPE_REDACTED",
	}
	ValueType_value = map[string]int32{
		"VALUE_TYPE_UNSPECIFIED": 0,
		"VALUE_TYPE_RAW":         1,
		"VALUE_TYPE_HASHED":      2,
		"VALUE_TYPE_REDACTED":    3,
	}
)

func (x ValueType) Enum() *ValueType {
	p := new(ValueType)
	*p = x
	return p
}

func (x ValueType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ValueType) Descriptor() protoreflect.EnumDescriptor {
	return file_ai_traceable_platform_apiinspection_v1_value_proto_enumTypes[0].Descriptor()
}

func (ValueType) Type() protoreflect.EnumType {
	return &file_ai_traceable_platform_apiinspection_v1_value_proto_enumTypes[0]
}

func (x ValueType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ValueType.Descriptor instead.
func (ValueType) EnumDescriptor() ([]byte, []int) {
	return file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescGZIP(), []int{0}
}

type Value struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value     string    `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	ValueType ValueType `protobuf:"varint,2,opt,name=value_type,json=valueType,proto3,enum=ai.traceable.platform.apiinspection.v1.ValueType" json:"value_type,omitempty"`
}

func (x *Value) Reset() {
	*x = Value{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ai_traceable_platform_apiinspection_v1_value_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Value) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Value) ProtoMessage() {}

func (x *Value) ProtoReflect() protoreflect.Message {
	mi := &file_ai_traceable_platform_apiinspection_v1_value_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Value.ProtoReflect.Descriptor instead.
func (*Value) Descriptor() ([]byte, []int) {
	return file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescGZIP(), []int{0}
}

func (x *Value) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Value) GetValueType() ValueType {
	if x != nil {
		return x.ValueType
	}
	return ValueType_VALUE_TYPE_UNSPECIFIED
}

var File_ai_traceable_platform_apiinspection_v1_value_proto protoreflect.FileDescriptor

var file_ai_traceable_platform_apiinspection_v1_value_proto_rawDesc = []byte{
	0x0a, 0x32, 0x61, 0x69, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65, 0x2f, 0x70,
	0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73, 0x70, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x26, 0x61, 0x69, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62,
	0x6c, 0x65, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x69,
	0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x22, 0x6f, 0x0a, 0x05,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x50, 0x0a, 0x0a, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x31, 0x2e, 0x61, 0x69, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x61, 0x62, 0x6c, 0x65, 0x2e, 0x70,
	0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x69, 0x6e, 0x73, 0x70, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x09, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x2a, 0x6b, 0x0a,
	0x09, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x16, 0x56, 0x41,
	0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49,
	0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x52, 0x41, 0x57, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x56, 0x41,
	0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x48, 0x41, 0x53, 0x48, 0x45, 0x44, 0x10,
	0x02, 0x12, 0x17, 0x0a, 0x13, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x52, 0x45, 0x44, 0x41, 0x43, 0x54, 0x45, 0x44, 0x10, 0x03, 0x42, 0x02, 0x50, 0x01, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescOnce sync.Once
	file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescData = file_ai_traceable_platform_apiinspection_v1_value_proto_rawDesc
)

func file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescGZIP() []byte {
	file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescOnce.Do(func() {
		file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescData = protoimpl.X.CompressGZIP(file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescData)
	})
	return file_ai_traceable_platform_apiinspection_v1_value_proto_rawDescData
}

var file_ai_traceable_platform_apiinspection_v1_value_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ai_traceable_platform_apiinspection_v1_value_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ai_traceable_platform_apiinspection_v1_value_proto_goTypes = []interface{}{
	(ValueType)(0), // 0: ai.traceable.platform.apiinspection.v1.ValueType
	(*Value)(nil),  // 1: ai.traceable.platform.apiinspection.v1.Value
}
var file_ai_traceable_platform_apiinspection_v1_value_proto_depIdxs = []int32{
	0, // 0: ai.traceable.platform.apiinspection.v1.Value.value_type:type_name -> ai.traceable.platform.apiinspection.v1.ValueType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ai_traceable_platform_apiinspection_v1_value_proto_init() }
func file_ai_traceable_platform_apiinspection_v1_value_proto_init() {
	if File_ai_traceable_platform_apiinspection_v1_value_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ai_traceable_platform_apiinspection_v1_value_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Value); i {
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
			RawDescriptor: file_ai_traceable_platform_apiinspection_v1_value_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ai_traceable_platform_apiinspection_v1_value_proto_goTypes,
		DependencyIndexes: file_ai_traceable_platform_apiinspection_v1_value_proto_depIdxs,
		EnumInfos:         file_ai_traceable_platform_apiinspection_v1_value_proto_enumTypes,
		MessageInfos:      file_ai_traceable_platform_apiinspection_v1_value_proto_msgTypes,
	}.Build()
	File_ai_traceable_platform_apiinspection_v1_value_proto = out.File
	file_ai_traceable_platform_apiinspection_v1_value_proto_rawDesc = nil
	file_ai_traceable_platform_apiinspection_v1_value_proto_goTypes = nil
	file_ai_traceable_platform_apiinspection_v1_value_proto_depIdxs = nil
}
