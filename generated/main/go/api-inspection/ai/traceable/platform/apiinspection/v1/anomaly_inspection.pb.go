// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api-inspection/ai/traceable/platform/apiinspection/v1/anomaly_inspection.proto

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
	return fileDescriptor_d53830708d6ee996, []int{0}
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
	return fileDescriptor_d53830708d6ee996, []int{1}
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
	proto.RegisterFile("api-inspection/ai/traceable/platform/apiinspection/v1/anomaly_inspection.proto", fileDescriptor_d53830708d6ee996)
}

var fileDescriptor_d53830708d6ee996 = []byte{
	// 255 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0xcd, 0x4a, 0xc4, 0x30,
	0x14, 0x85, 0x49, 0x47, 0x05, 0x33, 0x3f, 0x32, 0x5d, 0x75, 0x59, 0x47, 0x94, 0x6e, 0x4c, 0x19,
	0xc5, 0x07, 0xd0, 0x9d, 0xe0, 0x88, 0xd4, 0x07, 0x08, 0x77, 0xd2, 0xab, 0x5e, 0x48, 0x9a, 0x90,
	0xc4, 0x82, 0x2f, 0xe1, 0x33, 0xcb, 0xb4, 0xb6, 0xce, 0xec, 0x5c, 0xe6, 0xcb, 0xe1, 0xe3, 0x9c,
	0xcb, 0x9f, 0xc1, 0xd1, 0x35, 0x35, 0xc1, 0xa1, 0x8a, 0x64, 0x9b, 0x12, 0xa8, 0x8c, 0x1e, 0x14,
	0xc2, 0x56, 0x63, 0xe9, 0x34, 0xc4, 0x37, 0xeb, 0x4d, 0x09, 0x8e, 0xf6, 0x32, 0xed, 0xba, 0x84,
	0xc6, 0x1a, 0xd0, 0x5f, 0xf2, 0x8f, 0x0a, 0xe7, 0x6d, 0xb4, 0xe9, 0x15, 0x90, 0x18, 0x05, 0x62,
	0x10, 0x88, 0x03, 0x81, 0x68, 0xd7, 0xab, 0x6f, 0xc6, 0xe7, 0x1b, 0x5b, 0xbf, 0xa2, 0xba, 0xef,
	0x55, 0xe9, 0x82, 0x27, 0x54, 0x67, 0x2c, 0x67, 0xc5, 0x69, 0x95, 0x50, 0x9d, 0x5e, 0xf0, 0xb9,
	0x81, 0xa8, 0x3e, 0xa4, 0xc1, 0x10, 0xe0, 0x1d, 0xb3, 0xa4, 0xfb, 0x9a, 0x75, 0x70, 0xd3, 0xb3,
	0xf4, 0x9c, 0xcf, 0xfc, 0xa7, 0xc6, 0x31, 0x33, 0xe9, 0x32, 0xd3, 0x1d, 0x1b, 0x22, 0x97, 0x7c,
	0xe1, 0xc0, 0x43, 0x63, 0x09, 0xa4, 0xc6, 0x16, 0x75, 0x76, 0x94, 0xb3, 0xe2, 0xb8, 0x9a, 0x0f,
	0xf4, 0x69, 0x07, 0x57, 0x2d, 0x5f, 0xfe, 0x36, 0x79, 0x1c, 0x8b, 0xa6, 0xc0, 0x97, 0xc6, 0xd6,
	0x32, 0xa0, 0x92, 0xfd, 0x62, 0xc2, 0x90, 0xb1, 0x7c, 0x52, 0x4c, 0x6f, 0xee, 0xc4, 0xff, 0x96,
	0x8a, 0x83, 0x95, 0xd5, 0x99, 0xd9, 0x7b, 0x12, 0x86, 0x87, 0xe4, 0x85, 0x6d, 0x4f, 0xba, 0xdb,
	0xdd, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff, 0xa7, 0x82, 0xac, 0x2e, 0x8d, 0x01, 0x00, 0x00,
}