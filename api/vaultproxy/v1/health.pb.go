// Copyright 2023 Nautes Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.23.2
// source: api/vaultproxy/v1/health.proto

package v1

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

type HealthRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *HealthRequest) Reset() {
	*x = HealthRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_vaultproxy_v1_health_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HealthRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthRequest) ProtoMessage() {}

func (x *HealthRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_vaultproxy_v1_health_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthRequest.ProtoReflect.Descriptor instead.
func (*HealthRequest) Descriptor() ([]byte, []int) {
	return file_api_vaultproxy_v1_health_proto_rawDescGZIP(), []int{0}
}

type HealthReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StandBy bool `protobuf:"varint,1,opt,name=standBy,proto3" json:"standBy,omitempty"`
	Vault   bool `protobuf:"varint,2,opt,name=vault,proto3" json:"vault,omitempty"`
}

func (x *HealthReply) Reset() {
	*x = HealthReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_vaultproxy_v1_health_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HealthReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthReply) ProtoMessage() {}

func (x *HealthReply) ProtoReflect() protoreflect.Message {
	mi := &file_api_vaultproxy_v1_health_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthReply.ProtoReflect.Descriptor instead.
func (*HealthReply) Descriptor() ([]byte, []int) {
	return file_api_vaultproxy_v1_health_proto_rawDescGZIP(), []int{1}
}

func (x *HealthReply) GetStandBy() bool {
	if x != nil {
		return x.StandBy
	}
	return false
}

func (x *HealthReply) GetVault() bool {
	if x != nil {
		return x.Vault
	}
	return false
}

var File_api_vaultproxy_v1_health_proto protoreflect.FileDescriptor

var file_api_vaultproxy_v1_health_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2f, 0x76, 0x31, 0x2f, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x11, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x0f, 0x0a, 0x0d, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x3d, 0x0a, 0x0b, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x52, 0x65, 0x70, 0x6c,
	0x79, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x42, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x07, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x42, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x76, 0x61, 0x75, 0x6c,
	0x74, 0x32, 0x65, 0x0a, 0x06, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x12, 0x5b, 0x0a, 0x06, 0x48,
	0x65, 0x61, 0x6c, 0x74, 0x68, 0x12, 0x20, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x61, 0x75, 0x6c,
	0x74, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x61,
	0x75, 0x6c, 0x74, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x65, 0x61, 0x6c,
	0x74, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x0f, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x09, 0x12,
	0x07, 0x2f, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x42, 0x37, 0x0a, 0x11, 0x61, 0x70, 0x69, 0x2e,
	0x76, 0x61, 0x75, 0x6c, 0x74, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x50, 0x01, 0x5a,
	0x20, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x3b, 0x76,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_vaultproxy_v1_health_proto_rawDescOnce sync.Once
	file_api_vaultproxy_v1_health_proto_rawDescData = file_api_vaultproxy_v1_health_proto_rawDesc
)

func file_api_vaultproxy_v1_health_proto_rawDescGZIP() []byte {
	file_api_vaultproxy_v1_health_proto_rawDescOnce.Do(func() {
		file_api_vaultproxy_v1_health_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_vaultproxy_v1_health_proto_rawDescData)
	})
	return file_api_vaultproxy_v1_health_proto_rawDescData
}

var file_api_vaultproxy_v1_health_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_api_vaultproxy_v1_health_proto_goTypes = []interface{}{
	(*HealthRequest)(nil), // 0: api.vaultproxy.v1.HealthRequest
	(*HealthReply)(nil),   // 1: api.vaultproxy.v1.HealthReply
}
var file_api_vaultproxy_v1_health_proto_depIdxs = []int32{
	0, // 0: api.vaultproxy.v1.Health.Health:input_type -> api.vaultproxy.v1.HealthRequest
	1, // 1: api.vaultproxy.v1.Health.Health:output_type -> api.vaultproxy.v1.HealthReply
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_api_vaultproxy_v1_health_proto_init() }
func file_api_vaultproxy_v1_health_proto_init() {
	if File_api_vaultproxy_v1_health_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_vaultproxy_v1_health_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HealthRequest); i {
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
		file_api_vaultproxy_v1_health_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HealthReply); i {
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
			RawDescriptor: file_api_vaultproxy_v1_health_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_vaultproxy_v1_health_proto_goTypes,
		DependencyIndexes: file_api_vaultproxy_v1_health_proto_depIdxs,
		MessageInfos:      file_api_vaultproxy_v1_health_proto_msgTypes,
	}.Build()
	File_api_vaultproxy_v1_health_proto = out.File
	file_api_vaultproxy_v1_health_proto_rawDesc = nil
	file_api_vaultproxy_v1_health_proto_goTypes = nil
	file_api_vaultproxy_v1_health_proto_depIdxs = nil
}
