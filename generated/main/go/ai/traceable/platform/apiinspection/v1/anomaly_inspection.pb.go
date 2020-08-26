// Code generated by protoc-gen-go. DO NOT EDIT.
// source: ai/traceable/platform/apiinspection/v1/anomaly_inspection.proto

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

// Anomaly messages
type ModSecAnomaly struct {
	Id                   string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	MatchMessage         string   `protobuf:"bytes,2,opt,name=match_message,json=matchMessage,proto3" json:"match_message,omitempty"`
	RuleMessage          string   `protobuf:"bytes,3,opt,name=rule_message,json=ruleMessage,proto3" json:"rule_message,omitempty"`
	ParanoiaLevel        int32    `protobuf:"varint,4,opt,name=paranoia_level,json=paranoiaLevel,proto3" json:"paranoia_level,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ModSecAnomaly) Reset()         { *m = ModSecAnomaly{} }
func (m *ModSecAnomaly) String() string { return proto.CompactTextString(m) }
func (*ModSecAnomaly) ProtoMessage()    {}
func (*ModSecAnomaly) Descriptor() ([]byte, []int) {
	return fileDescriptor_cb52005ada329d41, []int{0}
}

func (m *ModSecAnomaly) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ModSecAnomaly.Unmarshal(m, b)
}
func (m *ModSecAnomaly) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ModSecAnomaly.Marshal(b, m, deterministic)
}
func (m *ModSecAnomaly) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ModSecAnomaly.Merge(m, src)
}
func (m *ModSecAnomaly) XXX_Size() int {
	return xxx_messageInfo_ModSecAnomaly.Size(m)
}
func (m *ModSecAnomaly) XXX_DiscardUnknown() {
	xxx_messageInfo_ModSecAnomaly.DiscardUnknown(m)
}

var xxx_messageInfo_ModSecAnomaly proto.InternalMessageInfo

func (m *ModSecAnomaly) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *ModSecAnomaly) GetMatchMessage() string {
	if m != nil {
		return m.MatchMessage
	}
	return ""
}

func (m *ModSecAnomaly) GetRuleMessage() string {
	if m != nil {
		return m.RuleMessage
	}
	return ""
}

func (m *ModSecAnomaly) GetParanoiaLevel() int32 {
	if m != nil {
		return m.ParanoiaLevel
	}
	return 0
}

// Metadata inspection for a single value
type AnomalyInspection struct {
	ModSecAnomalies      []*ModSecAnomaly `protobuf:"bytes,1,rep,name=mod_sec_anomalies,json=modSecAnomalies,proto3" json:"mod_sec_anomalies,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *AnomalyInspection) Reset()         { *m = AnomalyInspection{} }
func (m *AnomalyInspection) String() string { return proto.CompactTextString(m) }
func (*AnomalyInspection) ProtoMessage()    {}
func (*AnomalyInspection) Descriptor() ([]byte, []int) {
	return fileDescriptor_cb52005ada329d41, []int{1}
}

func (m *AnomalyInspection) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AnomalyInspection.Unmarshal(m, b)
}
func (m *AnomalyInspection) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AnomalyInspection.Marshal(b, m, deterministic)
}
func (m *AnomalyInspection) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AnomalyInspection.Merge(m, src)
}
func (m *AnomalyInspection) XXX_Size() int {
	return xxx_messageInfo_AnomalyInspection.Size(m)
}
func (m *AnomalyInspection) XXX_DiscardUnknown() {
	xxx_messageInfo_AnomalyInspection.DiscardUnknown(m)
}

var xxx_messageInfo_AnomalyInspection proto.InternalMessageInfo

func (m *AnomalyInspection) GetModSecAnomalies() []*ModSecAnomaly {
	if m != nil {
		return m.ModSecAnomalies
	}
	return nil
}

func init() {
	proto.RegisterType((*ModSecAnomaly)(nil), "ai.traceable.platform.apiinspection.v1.ModSecAnomaly")
	proto.RegisterType((*AnomalyInspection)(nil), "ai.traceable.platform.apiinspection.v1.AnomalyInspection")
}

func init() {
	proto.RegisterFile("ai/traceable/platform/apiinspection/v1/anomaly_inspection.proto", fileDescriptor_cb52005ada329d41)
}

var fileDescriptor_cb52005ada329d41 = []byte{
	// 250 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0xc1, 0x4a, 0xc4, 0x30,
	0x14, 0x45, 0x49, 0x47, 0x05, 0x33, 0xd3, 0x91, 0xe9, 0xaa, 0xcb, 0x3a, 0xa2, 0x74, 0x95, 0x32,
	0x8a, 0x6b, 0xd1, 0x9d, 0xe0, 0x80, 0xd4, 0x0f, 0x08, 0x6f, 0xd2, 0xa7, 0x3e, 0x48, 0x9a, 0x90,
	0xc4, 0x82, 0x3f, 0xe1, 0x37, 0xcb, 0xb4, 0xb6, 0x3a, 0x3b, 0x97, 0x39, 0xb9, 0x1c, 0xee, 0x7d,
	0xfc, 0x0e, 0xa8, 0x8a, 0x1e, 0x14, 0xc2, 0x4e, 0x63, 0xe5, 0x34, 0xc4, 0x57, 0xeb, 0x4d, 0x05,
	0x8e, 0xa8, 0x0d, 0x0e, 0x55, 0x24, 0xdb, 0x56, 0xdd, 0xa6, 0x82, 0xd6, 0x1a, 0xd0, 0x9f, 0xf2,
	0x97, 0x0a, 0xe7, 0x6d, 0xb4, 0xd9, 0x15, 0x90, 0x98, 0x04, 0x62, 0x14, 0x88, 0x03, 0x81, 0xe8,
	0x36, 0xeb, 0x2f, 0xc6, 0xd3, 0xad, 0x6d, 0x5e, 0x50, 0xdd, 0x0f, 0xaa, 0x6c, 0xc9, 0x13, 0x6a,
	0x72, 0x56, 0xb0, 0xf2, 0xb4, 0x4e, 0xa8, 0xc9, 0x2e, 0x78, 0x6a, 0x20, 0xaa, 0x77, 0x69, 0x30,
	0x04, 0x78, 0xc3, 0x3c, 0xe9, 0xbf, 0x16, 0x3d, 0xdc, 0x0e, 0x2c, 0x3b, 0xe7, 0x0b, 0xff, 0xa1,
	0x71, 0xca, 0xcc, 0xfa, 0xcc, 0x7c, 0xcf, 0xc6, 0xc8, 0x25, 0x5f, 0x3a, 0xf0, 0xd0, 0x5a, 0x02,
	0xa9, 0xb1, 0x43, 0x9d, 0x1f, 0x15, 0xac, 0x3c, 0xae, 0xd3, 0x91, 0x3e, 0xed, 0xe1, 0xba, 0xe3,
	0xab, 0x9f, 0x26, 0x8f, 0x53, 0xd1, 0x0c, 0xf8, 0xca, 0xd8, 0x46, 0x06, 0x54, 0x72, 0x58, 0x4c,
	0x18, 0x72, 0x56, 0xcc, 0xca, 0xf9, 0xf5, 0xad, 0xf8, 0xdf, 0x52, 0x71, 0xb0, 0xb2, 0x3e, 0x33,
	0x7f, 0x9e, 0x84, 0xe1, 0x21, 0x79, 0x66, 0xbb, 0x93, 0xfe, 0x76, 0x37, 0xdf, 0x01, 0x00, 0x00,
	0xff, 0xff, 0x27, 0x3e, 0xf8, 0xe0, 0x7e, 0x01, 0x00, 0x00,
}