// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: keyprovider/keyprovider.proto

package keyprovider

import (
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

type KeyProviderKeyWrapProtocolInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyProviderKeyWrapProtocolInput []byte `protobuf:"bytes,1,opt,name=KeyProviderKeyWrapProtocolInput,proto3" json:"KeyProviderKeyWrapProtocolInput,omitempty"`
}

func (x *KeyProviderKeyWrapProtocolInput) Reset() {
	*x = KeyProviderKeyWrapProtocolInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keyprovider_keyprovider_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyProviderKeyWrapProtocolInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyProviderKeyWrapProtocolInput) ProtoMessage() {}

func (x *KeyProviderKeyWrapProtocolInput) ProtoReflect() protoreflect.Message {
	mi := &file_keyprovider_keyprovider_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyProviderKeyWrapProtocolInput.ProtoReflect.Descriptor instead.
func (*KeyProviderKeyWrapProtocolInput) Descriptor() ([]byte, []int) {
	return file_keyprovider_keyprovider_proto_rawDescGZIP(), []int{0}
}

func (x *KeyProviderKeyWrapProtocolInput) GetKeyProviderKeyWrapProtocolInput() []byte {
	if x != nil {
		return x.KeyProviderKeyWrapProtocolInput
	}
	return nil
}

type KeyProviderKeyWrapProtocolOutput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyProviderKeyWrapProtocolOutput []byte `protobuf:"bytes,1,opt,name=KeyProviderKeyWrapProtocolOutput,proto3" json:"KeyProviderKeyWrapProtocolOutput,omitempty"`
}

func (x *KeyProviderKeyWrapProtocolOutput) Reset() {
	*x = KeyProviderKeyWrapProtocolOutput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keyprovider_keyprovider_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyProviderKeyWrapProtocolOutput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyProviderKeyWrapProtocolOutput) ProtoMessage() {}

func (x *KeyProviderKeyWrapProtocolOutput) ProtoReflect() protoreflect.Message {
	mi := &file_keyprovider_keyprovider_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyProviderKeyWrapProtocolOutput.ProtoReflect.Descriptor instead.
func (*KeyProviderKeyWrapProtocolOutput) Descriptor() ([]byte, []int) {
	return file_keyprovider_keyprovider_proto_rawDescGZIP(), []int{1}
}

func (x *KeyProviderKeyWrapProtocolOutput) GetKeyProviderKeyWrapProtocolOutput() []byte {
	if x != nil {
		return x.KeyProviderKeyWrapProtocolOutput
	}
	return nil
}

type KeyProviderGetReportInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ReportDataHexString string `protobuf:"bytes,1,opt,name=reportDataHexString,proto3" json:"reportDataHexString,omitempty"`
}

func (x *KeyProviderGetReportInput) Reset() {
	*x = KeyProviderGetReportInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keyprovider_keyprovider_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyProviderGetReportInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyProviderGetReportInput) ProtoMessage() {}

func (x *KeyProviderGetReportInput) ProtoReflect() protoreflect.Message {
	mi := &file_keyprovider_keyprovider_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyProviderGetReportInput.ProtoReflect.Descriptor instead.
func (*KeyProviderGetReportInput) Descriptor() ([]byte, []int) {
	return file_keyprovider_keyprovider_proto_rawDescGZIP(), []int{2}
}

func (x *KeyProviderGetReportInput) GetReportDataHexString() string {
	if x != nil {
		return x.ReportDataHexString
	}
	return ""
}

type KeyProviderGetReportOutput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ReportHexString string `protobuf:"bytes,1,opt,name=reportHexString,proto3" json:"reportHexString,omitempty"`
}

func (x *KeyProviderGetReportOutput) Reset() {
	*x = KeyProviderGetReportOutput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keyprovider_keyprovider_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyProviderGetReportOutput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyProviderGetReportOutput) ProtoMessage() {}

func (x *KeyProviderGetReportOutput) ProtoReflect() protoreflect.Message {
	mi := &file_keyprovider_keyprovider_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyProviderGetReportOutput.ProtoReflect.Descriptor instead.
func (*KeyProviderGetReportOutput) Descriptor() ([]byte, []int) {
	return file_keyprovider_keyprovider_proto_rawDescGZIP(), []int{3}
}

func (x *KeyProviderGetReportOutput) GetReportHexString() string {
	if x != nil {
		return x.ReportHexString
	}
	return ""
}

type HelloRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *HelloRequest) Reset() {
	*x = HelloRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keyprovider_keyprovider_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HelloRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HelloRequest) ProtoMessage() {}

func (x *HelloRequest) ProtoReflect() protoreflect.Message {
	mi := &file_keyprovider_keyprovider_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HelloRequest.ProtoReflect.Descriptor instead.
func (*HelloRequest) Descriptor() ([]byte, []int) {
	return file_keyprovider_keyprovider_proto_rawDescGZIP(), []int{4}
}

func (x *HelloRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// The response message containing the greetings
type HelloReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *HelloReply) Reset() {
	*x = HelloReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keyprovider_keyprovider_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HelloReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HelloReply) ProtoMessage() {}

func (x *HelloReply) ProtoReflect() protoreflect.Message {
	mi := &file_keyprovider_keyprovider_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HelloReply.ProtoReflect.Descriptor instead.
func (*HelloReply) Descriptor() ([]byte, []int) {
	return file_keyprovider_keyprovider_proto_rawDescGZIP(), []int{5}
}

func (x *HelloReply) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_keyprovider_keyprovider_proto protoreflect.FileDescriptor

var file_keyprovider_keyprovider_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2f, 0x6b, 0x65,
	0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0b, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x22, 0x6b, 0x0a, 0x1f,
	0x6b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72,
	0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x12,
	0x48, 0x0a, 0x1f, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65,
	0x79, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x6e, 0x70,
	0x75, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1f, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f,
	0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x6e, 0x0a, 0x20, 0x6b, 0x65, 0x79,
	0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x12, 0x4a, 0x0a,
	0x20, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57,
	0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x4f, 0x75, 0x74, 0x70, 0x75,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x20, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x22, 0x4d, 0x0a, 0x19, 0x6b, 0x65, 0x79,
	0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x12, 0x30, 0x0a, 0x13, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x44, 0x61, 0x74, 0x61, 0x48, 0x65, 0x78, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x13, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x48,
	0x65, 0x78, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x22, 0x46, 0x0a, 0x1a, 0x6b, 0x65, 0x79, 0x50,
	0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x12, 0x28, 0x0a, 0x0f, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x48, 0x65, 0x78, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0f, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x48, 0x65, 0x78, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x22, 0x22, 0x0a, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x22, 0x26, 0x0a, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x52, 0x65, 0x70,
	0x6c, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x8c, 0x03, 0x0a,
	0x12, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x12, 0x68, 0x0a, 0x07, 0x57, 0x72, 0x61, 0x70, 0x4b, 0x65, 0x79, 0x12, 0x2c,
	0x2e, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x6b, 0x65, 0x79,
	0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x1a, 0x2d, 0x2e, 0x6b,
	0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x6b, 0x65, 0x79, 0x50, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x22, 0x00, 0x12, 0x6a, 0x0a,
	0x09, 0x55, 0x6e, 0x57, 0x72, 0x61, 0x70, 0x4b, 0x65, 0x79, 0x12, 0x2c, 0x2e, 0x6b, 0x65, 0x79,
	0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x6b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x1a, 0x2d, 0x2e, 0x6b, 0x65, 0x79, 0x70, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x6b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x4b, 0x65, 0x79, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
	0x6c, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x22, 0x00, 0x12, 0x5e, 0x0a, 0x09, 0x47, 0x65, 0x74,
	0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x26, 0x2e, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x2e, 0x6b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72,
	0x47, 0x65, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x1a, 0x27,
	0x2e, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x6b, 0x65, 0x79,
	0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x22, 0x00, 0x12, 0x40, 0x0a, 0x08, 0x53, 0x61, 0x79,
	0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x12, 0x19, 0x2e, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x64, 0x65, 0x72, 0x2e, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x17, 0x2e, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x48,
	0x65, 0x6c, 0x6c, 0x6f, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x0f, 0x5a, 0x0d, 0x2e,
	0x2f, 0x6b, 0x65, 0x79, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_keyprovider_keyprovider_proto_rawDescOnce sync.Once
	file_keyprovider_keyprovider_proto_rawDescData = file_keyprovider_keyprovider_proto_rawDesc
)

func file_keyprovider_keyprovider_proto_rawDescGZIP() []byte {
	file_keyprovider_keyprovider_proto_rawDescOnce.Do(func() {
		file_keyprovider_keyprovider_proto_rawDescData = protoimpl.X.CompressGZIP(file_keyprovider_keyprovider_proto_rawDescData)
	})
	return file_keyprovider_keyprovider_proto_rawDescData
}

var file_keyprovider_keyprovider_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_keyprovider_keyprovider_proto_goTypes = []interface{}{
	(*KeyProviderKeyWrapProtocolInput)(nil),  // 0: keyprovider.keyProviderKeyWrapProtocolInput
	(*KeyProviderKeyWrapProtocolOutput)(nil), // 1: keyprovider.keyProviderKeyWrapProtocolOutput
	(*KeyProviderGetReportInput)(nil),        // 2: keyprovider.keyProviderGetReportInput
	(*KeyProviderGetReportOutput)(nil),       // 3: keyprovider.keyProviderGetReportOutput
	(*HelloRequest)(nil),                     // 4: keyprovider.HelloRequest
	(*HelloReply)(nil),                       // 5: keyprovider.HelloReply
}
var file_keyprovider_keyprovider_proto_depIdxs = []int32{
	0, // 0: keyprovider.KeyProviderService.WrapKey:input_type -> keyprovider.keyProviderKeyWrapProtocolInput
	0, // 1: keyprovider.KeyProviderService.UnWrapKey:input_type -> keyprovider.keyProviderKeyWrapProtocolInput
	2, // 2: keyprovider.KeyProviderService.GetReport:input_type -> keyprovider.keyProviderGetReportInput
	4, // 3: keyprovider.KeyProviderService.SayHello:input_type -> keyprovider.HelloRequest
	1, // 4: keyprovider.KeyProviderService.WrapKey:output_type -> keyprovider.keyProviderKeyWrapProtocolOutput
	1, // 5: keyprovider.KeyProviderService.UnWrapKey:output_type -> keyprovider.keyProviderKeyWrapProtocolOutput
	3, // 6: keyprovider.KeyProviderService.GetReport:output_type -> keyprovider.keyProviderGetReportOutput
	5, // 7: keyprovider.KeyProviderService.SayHello:output_type -> keyprovider.HelloReply
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_keyprovider_keyprovider_proto_init() }
func file_keyprovider_keyprovider_proto_init() {
	if File_keyprovider_keyprovider_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_keyprovider_keyprovider_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyProviderKeyWrapProtocolInput); i {
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
		file_keyprovider_keyprovider_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyProviderKeyWrapProtocolOutput); i {
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
		file_keyprovider_keyprovider_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyProviderGetReportInput); i {
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
		file_keyprovider_keyprovider_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyProviderGetReportOutput); i {
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
		file_keyprovider_keyprovider_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HelloRequest); i {
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
		file_keyprovider_keyprovider_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HelloReply); i {
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
			RawDescriptor: file_keyprovider_keyprovider_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_keyprovider_keyprovider_proto_goTypes,
		DependencyIndexes: file_keyprovider_keyprovider_proto_depIdxs,
		MessageInfos:      file_keyprovider_keyprovider_proto_msgTypes,
	}.Build()
	File_keyprovider_keyprovider_proto = out.File
	file_keyprovider_keyprovider_proto_rawDesc = nil
	file_keyprovider_keyprovider_proto_goTypes = nil
	file_keyprovider_keyprovider_proto_depIdxs = nil
}
