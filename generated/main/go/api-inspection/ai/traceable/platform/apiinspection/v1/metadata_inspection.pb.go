// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api-inspection/ai/traceable/platform/apiinspection/v1/metadata_inspection.proto

package ai_traceable_platform_apiinspection_v1

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Param Value Metadata
type ParamValueType int32

const (
	ParamValueType_UNKNOWN ParamValueType = 0
	ParamValueType_BOOLEAN ParamValueType = 1
	ParamValueType_INTEGER ParamValueType = 2
	ParamValueType_FLOAT   ParamValueType = 3
	ParamValueType_CHAR    ParamValueType = 4
	ParamValueType_STRING  ParamValueType = 5
)

var ParamValueType_name = map[int32]string{
	0: "UNKNOWN",
	1: "BOOLEAN",
	2: "INTEGER",
	3: "FLOAT",
	4: "CHAR",
	5: "STRING",
}

var ParamValueType_value = map[string]int32{
	"UNKNOWN": 0,
	"BOOLEAN": 1,
	"INTEGER": 2,
	"FLOAT":   3,
	"CHAR":    4,
	"STRING":  5,
}

func (x ParamValueType) String() string {
	return proto.EnumName(ParamValueType_name, int32(x))
}

func (ParamValueType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8f17bbbbe2fb6f1f, []int{0}
}

// Special Character Inspection
type SpecialCharacterInspection struct {
	StartsWithPipe  bool `protobuf:"varint,1,opt,name=starts_with_pipe,json=startsWithPipe,proto3" json:"starts_with_pipe,omitempty"`
	ContainsNosqlOp bool `protobuf:"varint,2,opt,name=contains_nosql_op,json=containsNosqlOp,proto3" json:"contains_nosql_op,omitempty"`
	// Key: ASCII code of special char
	// Value: Number of occurrences
	SpecialCharDistribution map[int32]int32 `protobuf:"bytes,3,rep,name=special_char_distribution,json=specialCharDistribution,proto3" json:"special_char_distribution,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral    struct{}        `json:"-"`
	XXX_unrecognized        []byte          `json:"-"`
	XXX_sizecache           int32           `json:"-"`
}

func (m *SpecialCharacterInspection) Reset()         { *m = SpecialCharacterInspection{} }
func (m *SpecialCharacterInspection) String() string { return proto.CompactTextString(m) }
func (*SpecialCharacterInspection) ProtoMessage()    {}
func (*SpecialCharacterInspection) Descriptor() ([]byte, []int) {
	return fileDescriptor_8f17bbbbe2fb6f1f, []int{0}
}

func (m *SpecialCharacterInspection) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SpecialCharacterInspection.Unmarshal(m, b)
}
func (m *SpecialCharacterInspection) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SpecialCharacterInspection.Marshal(b, m, deterministic)
}
func (m *SpecialCharacterInspection) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SpecialCharacterInspection.Merge(m, src)
}
func (m *SpecialCharacterInspection) XXX_Size() int {
	return xxx_messageInfo_SpecialCharacterInspection.Size(m)
}
func (m *SpecialCharacterInspection) XXX_DiscardUnknown() {
	xxx_messageInfo_SpecialCharacterInspection.DiscardUnknown(m)
}

var xxx_messageInfo_SpecialCharacterInspection proto.InternalMessageInfo

func (m *SpecialCharacterInspection) GetStartsWithPipe() bool {
	if m != nil {
		return m.StartsWithPipe
	}
	return false
}

func (m *SpecialCharacterInspection) GetContainsNosqlOp() bool {
	if m != nil {
		return m.ContainsNosqlOp
	}
	return false
}

func (m *SpecialCharacterInspection) GetSpecialCharDistribution() map[int32]int32 {
	if m != nil {
		return m.SpecialCharDistribution
	}
	return nil
}

// Metadata inspection for a single value
type MetadataInspection struct {
	Value                 *Value                      `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	Type                  ParamValueType              `protobuf:"varint,2,opt,name=type,proto3,enum=ai.traceable.platform.apiinspection.v1.ParamValueType" json:"type,omitempty"`
	Length                int32                       `protobuf:"varint,3,opt,name=length,proto3" json:"length,omitempty"`
	SpecialCharInspection *SpecialCharacterInspection `protobuf:"bytes,4,opt,name=special_char_inspection,json=specialCharInspection,proto3" json:"special_char_inspection,omitempty"`
	XXX_NoUnkeyedLiteral  struct{}                    `json:"-"`
	XXX_unrecognized      []byte                      `json:"-"`
	XXX_sizecache         int32                       `json:"-"`
}

func (m *MetadataInspection) Reset()         { *m = MetadataInspection{} }
func (m *MetadataInspection) String() string { return proto.CompactTextString(m) }
func (*MetadataInspection) ProtoMessage()    {}
func (*MetadataInspection) Descriptor() ([]byte, []int) {
	return fileDescriptor_8f17bbbbe2fb6f1f, []int{1}
}

func (m *MetadataInspection) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MetadataInspection.Unmarshal(m, b)
}
func (m *MetadataInspection) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MetadataInspection.Marshal(b, m, deterministic)
}
func (m *MetadataInspection) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MetadataInspection.Merge(m, src)
}
func (m *MetadataInspection) XXX_Size() int {
	return xxx_messageInfo_MetadataInspection.Size(m)
}
func (m *MetadataInspection) XXX_DiscardUnknown() {
	xxx_messageInfo_MetadataInspection.DiscardUnknown(m)
}

var xxx_messageInfo_MetadataInspection proto.InternalMessageInfo

func (m *MetadataInspection) GetValue() *Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *MetadataInspection) GetType() ParamValueType {
	if m != nil {
		return m.Type
	}
	return ParamValueType_UNKNOWN
}

func (m *MetadataInspection) GetLength() int32 {
	if m != nil {
		return m.Length
	}
	return 0
}

func (m *MetadataInspection) GetSpecialCharInspection() *SpecialCharacterInspection {
	if m != nil {
		return m.SpecialCharInspection
	}
	return nil
}

func init() {
	proto.RegisterEnum("ai.traceable.platform.apiinspection.v1.ParamValueType", ParamValueType_name, ParamValueType_value)
	proto.RegisterType((*SpecialCharacterInspection)(nil), "ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection")
	proto.RegisterMapType((map[int32]int32)(nil), "ai.traceable.platform.apiinspection.v1.SpecialCharacterInspection.SpecialCharDistributionEntry")
	proto.RegisterType((*MetadataInspection)(nil), "ai.traceable.platform.apiinspection.v1.MetadataInspection")
}

func init() {
	proto.RegisterFile("api-inspection/ai/traceable/platform/apiinspection/v1/metadata_inspection.proto", fileDescriptor_8f17bbbbe2fb6f1f)
}

var fileDescriptor_8f17bbbbe2fb6f1f = []byte{
	// 455 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x92, 0xdd, 0x6e, 0xd3, 0x30,
	0x14, 0xc7, 0x49, 0xd2, 0x94, 0x71, 0x2a, 0x95, 0x60, 0x01, 0x0b, 0x15, 0x17, 0xd3, 0x2e, 0x50,
	0x35, 0x69, 0x89, 0x56, 0x24, 0x84, 0xb8, 0x6b, 0x4b, 0x19, 0x1d, 0x23, 0xa9, 0xbc, 0xc2, 0xb8,
	0x8b, 0x4e, 0x33, 0x43, 0x2c, 0xd2, 0xc4, 0x38, 0x5e, 0x51, 0x79, 0x15, 0x9e, 0x84, 0x77, 0xe1,
	0x61, 0x50, 0x9c, 0x76, 0x4d, 0x25, 0x40, 0x15, 0xdc, 0xf9, 0x7c, 0xfd, 0xfe, 0xe7, 0xc3, 0x10,
	0xa2, 0xe0, 0xc7, 0x3c, 0x2b, 0x04, 0x8b, 0x15, 0xcf, 0x33, 0x1f, 0xb9, 0xaf, 0x24, 0xc6, 0x0c,
	0x67, 0x29, 0xf3, 0x45, 0x8a, 0xea, 0x63, 0x2e, 0xe7, 0x3e, 0x0a, 0x5e, 0xcb, 0x59, 0x9c, 0xf8,
	0x73, 0xa6, 0xf0, 0x0a, 0x15, 0x46, 0x1b, 0xb7, 0x27, 0x64, 0xae, 0x72, 0xf2, 0x04, 0xb9, 0x77,
	0x43, 0xf0, 0xd6, 0x04, 0x6f, 0x8b, 0xe0, 0x2d, 0x4e, 0x3a, 0xfd, 0x7f, 0x13, 0x5e, 0x60, 0x7a,
	0xcd, 0x2a, 0xa9, 0xc3, 0x9f, 0x26, 0x74, 0x2e, 0x04, 0x8b, 0x39, 0xa6, 0xc3, 0x04, 0x25, 0xc6,
	0x8a, 0xc9, 0xf1, 0x4d, 0x36, 0xe9, 0x82, 0x53, 0x28, 0x94, 0xaa, 0x88, 0xbe, 0x72, 0x95, 0x44,
	0x82, 0x0b, 0xe6, 0x1a, 0x07, 0x46, 0x77, 0x8f, 0xb6, 0x2b, 0xff, 0x25, 0x57, 0xc9, 0x84, 0x0b,
	0x46, 0x8e, 0xe0, 0x5e, 0x9c, 0x67, 0x0a, 0x79, 0x56, 0x44, 0x59, 0x5e, 0x7c, 0x49, 0xa3, 0x5c,
	0xb8, 0xa6, 0x4e, 0xbd, 0xbb, 0x0e, 0x04, 0xa5, 0x3f, 0x14, 0xe4, 0xbb, 0x01, 0x8f, 0x8a, 0x4a,
	0x34, 0x8a, 0x13, 0x94, 0xd1, 0x15, 0x2f, 0x94, 0xe4, 0xb3, 0xeb, 0x52, 0xd3, 0xb5, 0x0e, 0xac,
	0x6e, 0xab, 0x17, 0x79, 0xbb, 0x2d, 0xc1, 0xfb, 0x73, 0xf7, 0xf5, 0xd0, 0xcb, 0x9a, 0xc2, 0x28,
	0x53, 0x72, 0x49, 0xf7, 0x8b, 0xdf, 0x47, 0x3b, 0x67, 0xf0, 0xf8, 0x6f, 0x85, 0xc4, 0x01, 0xeb,
	0x33, 0x5b, 0xea, 0x35, 0xd8, 0xb4, 0x7c, 0x92, 0xfb, 0x60, 0xeb, 0x9d, 0xea, 0x79, 0x6d, 0x5a,
	0x19, 0x2f, 0xcc, 0xe7, 0xc6, 0xe1, 0x0f, 0x13, 0xc8, 0xdb, 0xd5, 0x9d, 0x6b, 0x6b, 0x1d, 0xae,
	0x0b, 0x4a, 0x48, 0xab, 0x77, 0xbc, 0xeb, 0xac, 0xef, 0xcb, 0xa2, 0x15, 0x9f, 0x9c, 0x41, 0x43,
	0x2d, 0x45, 0x25, 0xda, 0xee, 0x3d, 0xdb, 0x95, 0x31, 0x41, 0x89, 0x73, 0x0d, 0x9a, 0x2e, 0x05,
	0xa3, 0x9a, 0x41, 0x1e, 0x42, 0x33, 0x65, 0xd9, 0x27, 0x95, 0xb8, 0x96, 0x1e, 0x61, 0x65, 0x91,
	0x6f, 0xb0, 0xbf, 0x75, 0xa8, 0x0d, 0xca, 0x6d, 0xe8, 0xd6, 0x07, 0xff, 0x7f, 0x26, 0xfa, 0xa0,
	0x76, 0x89, 0x8d, 0xfb, 0xe8, 0x03, 0xb4, 0xb7, 0x7b, 0x25, 0x2d, 0xb8, 0xfd, 0x2e, 0x78, 0x13,
	0x84, 0x97, 0x81, 0x73, 0xab, 0x34, 0x06, 0x61, 0x78, 0x3e, 0xea, 0x07, 0x8e, 0x51, 0x1a, 0xe3,
	0x60, 0x3a, 0x3a, 0x1d, 0x51, 0xc7, 0x24, 0x77, 0xc0, 0x7e, 0x75, 0x1e, 0xf6, 0xa7, 0x8e, 0x45,
	0xf6, 0xa0, 0x31, 0x7c, 0xdd, 0xa7, 0x4e, 0x83, 0x00, 0x34, 0x2f, 0xa6, 0x74, 0x1c, 0x9c, 0x3a,
	0xf6, 0xc0, 0x9c, 0x18, 0xb3, 0xa6, 0xfe, 0xff, 0x4f, 0x7f, 0x05, 0x00, 0x00, 0xff, 0xff, 0x62,
	0x7e, 0xbe, 0x01, 0xbd, 0x03, 0x00, 0x00,
}
