// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.19.6
// source: v1/report/report.proto

package report

import (
	observability "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
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

type ReportRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Clusters     []string  `protobuf:"bytes,1,rep,name=Clusters,proto3" json:"Clusters,omitempty"`
	Namespaces   []string  `protobuf:"bytes,2,rep,name=Namespaces,proto3" json:"Namespaces,omitempty"`
	ResourceType []string  `protobuf:"bytes,3,rep,name=ResourceType,proto3" json:"ResourceType,omitempty"`
	ResourceName []string  `protobuf:"bytes,4,rep,name=ResourceName,proto3" json:"ResourceName,omitempty"`
	PodName      string    `protobuf:"bytes,5,opt,name=PodName,proto3" json:"PodName,omitempty"`
	MetaData     *MetaData `protobuf:"bytes,6,opt,name=MetaData,proto3" json:"MetaData,omitempty"`
	Operation    string    `protobuf:"bytes,7,opt,name=Operation,proto3" json:"Operation,omitempty"`
	Source       []string  `protobuf:"bytes,8,rep,name=Source,proto3" json:"Source,omitempty"`
	Destination  []string  `protobuf:"bytes,9,rep,name=Destination,proto3" json:"Destination,omitempty"`
}

func (x *ReportRequest) Reset() {
	*x = ReportRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReportRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReportRequest) ProtoMessage() {}

func (x *ReportRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReportRequest.ProtoReflect.Descriptor instead.
func (*ReportRequest) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{0}
}

func (x *ReportRequest) GetClusters() []string {
	if x != nil {
		return x.Clusters
	}
	return nil
}

func (x *ReportRequest) GetNamespaces() []string {
	if x != nil {
		return x.Namespaces
	}
	return nil
}

func (x *ReportRequest) GetResourceType() []string {
	if x != nil {
		return x.ResourceType
	}
	return nil
}

func (x *ReportRequest) GetResourceName() []string {
	if x != nil {
		return x.ResourceName
	}
	return nil
}

func (x *ReportRequest) GetPodName() string {
	if x != nil {
		return x.PodName
	}
	return ""
}

func (x *ReportRequest) GetMetaData() *MetaData {
	if x != nil {
		return x.MetaData
	}
	return nil
}

func (x *ReportRequest) GetOperation() string {
	if x != nil {
		return x.Operation
	}
	return ""
}

func (x *ReportRequest) GetSource() []string {
	if x != nil {
		return x.Source
	}
	return nil
}

func (x *ReportRequest) GetDestination() []string {
	if x != nil {
		return x.Destination
	}
	return nil
}

type ReportResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Clusters map[string]*ClusterData `protobuf:"bytes,1,rep,name=Clusters,proto3" json:"Clusters,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ReportResponse) Reset() {
	*x = ReportResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReportResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReportResponse) ProtoMessage() {}

func (x *ReportResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReportResponse.ProtoReflect.Descriptor instead.
func (*ReportResponse) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{1}
}

func (x *ReportResponse) GetClusters() map[string]*ClusterData {
	if x != nil {
		return x.Clusters
	}
	return nil
}

type ClusterData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClusterName string                    `protobuf:"bytes,1,opt,name=ClusterName,proto3" json:"ClusterName,omitempty"`
	Namespaces  map[string]*NamespaceData `protobuf:"bytes,2,rep,name=Namespaces,proto3" json:"Namespaces,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ClusterData) Reset() {
	*x = ClusterData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClusterData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClusterData) ProtoMessage() {}

func (x *ClusterData) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClusterData.ProtoReflect.Descriptor instead.
func (*ClusterData) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{2}
}

func (x *ClusterData) GetClusterName() string {
	if x != nil {
		return x.ClusterName
	}
	return ""
}

func (x *ClusterData) GetNamespaces() map[string]*NamespaceData {
	if x != nil {
		return x.Namespaces
	}
	return nil
}

type NamespaceData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NamespaceName string                       `protobuf:"bytes,1,opt,name=NamespaceName,proto3" json:"NamespaceName,omitempty"`
	ResourceTypes map[string]*ResourceTypeData `protobuf:"bytes,2,rep,name=ResourceTypes,proto3" json:"ResourceTypes,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *NamespaceData) Reset() {
	*x = NamespaceData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NamespaceData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NamespaceData) ProtoMessage() {}

func (x *NamespaceData) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NamespaceData.ProtoReflect.Descriptor instead.
func (*NamespaceData) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{3}
}

func (x *NamespaceData) GetNamespaceName() string {
	if x != nil {
		return x.NamespaceName
	}
	return ""
}

func (x *NamespaceData) GetResourceTypes() map[string]*ResourceTypeData {
	if x != nil {
		return x.ResourceTypes
	}
	return nil
}

type ResourceTypeData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResourceType string                   `protobuf:"bytes,1,opt,name=ResourceType,proto3" json:"ResourceType,omitempty"`
	Resources    map[string]*ResourceData `protobuf:"bytes,2,rep,name=Resources,proto3" json:"Resources,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ResourceTypeData) Reset() {
	*x = ResourceTypeData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceTypeData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceTypeData) ProtoMessage() {}

func (x *ResourceTypeData) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceTypeData.ProtoReflect.Descriptor instead.
func (*ResourceTypeData) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{4}
}

func (x *ResourceTypeData) GetResourceType() string {
	if x != nil {
		return x.ResourceType
	}
	return ""
}

func (x *ResourceTypeData) GetResources() map[string]*ResourceData {
	if x != nil {
		return x.Resources
	}
	return nil
}

type ResourceData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResourceType string       `protobuf:"bytes,1,opt,name=ResourceType,proto3" json:"ResourceType,omitempty"`
	ResourceName string       `protobuf:"bytes,2,opt,name=ResourceName,proto3" json:"ResourceName,omitempty"`
	MData        *MetaData    `protobuf:"bytes,3,opt,name=MData,proto3" json:"MData,omitempty"`
	SumData      *SummaryData `protobuf:"bytes,4,opt,name=SumData,proto3" json:"SumData,omitempty"`
}

func (x *ResourceData) Reset() {
	*x = ResourceData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceData) ProtoMessage() {}

func (x *ResourceData) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceData.ProtoReflect.Descriptor instead.
func (*ResourceData) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{5}
}

func (x *ResourceData) GetResourceType() string {
	if x != nil {
		return x.ResourceType
	}
	return ""
}

func (x *ResourceData) GetResourceName() string {
	if x != nil {
		return x.ResourceName
	}
	return ""
}

func (x *ResourceData) GetMData() *MetaData {
	if x != nil {
		return x.MData
	}
	return nil
}

func (x *ResourceData) GetSumData() *SummaryData {
	if x != nil {
		return x.SumData
	}
	return nil
}

type SummaryData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProcessData       []*observability.SysProcFileSummaryData `protobuf:"bytes,1,rep,name=ProcessData,proto3" json:"ProcessData,omitempty"`
	FileData          []*observability.SysProcFileSummaryData `protobuf:"bytes,2,rep,name=FileData,proto3" json:"FileData,omitempty"`
	IngressConnection []*observability.SysNwSummaryData       `protobuf:"bytes,3,rep,name=IngressConnection,proto3" json:"IngressConnection,omitempty"`
	EgressConnection  []*observability.SysNwSummaryData       `protobuf:"bytes,4,rep,name=EgressConnection,proto3" json:"EgressConnection,omitempty"`
	BindConnection    []*observability.SysNwSummaryData       `protobuf:"bytes,5,rep,name=BindConnection,proto3" json:"BindConnection,omitempty"`
}

func (x *SummaryData) Reset() {
	*x = SummaryData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SummaryData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SummaryData) ProtoMessage() {}

func (x *SummaryData) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SummaryData.ProtoReflect.Descriptor instead.
func (*SummaryData) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{6}
}

func (x *SummaryData) GetProcessData() []*observability.SysProcFileSummaryData {
	if x != nil {
		return x.ProcessData
	}
	return nil
}

func (x *SummaryData) GetFileData() []*observability.SysProcFileSummaryData {
	if x != nil {
		return x.FileData
	}
	return nil
}

func (x *SummaryData) GetIngressConnection() []*observability.SysNwSummaryData {
	if x != nil {
		return x.IngressConnection
	}
	return nil
}

func (x *SummaryData) GetEgressConnection() []*observability.SysNwSummaryData {
	if x != nil {
		return x.EgressConnection
	}
	return nil
}

func (x *SummaryData) GetBindConnection() []*observability.SysNwSummaryData {
	if x != nil {
		return x.BindConnection
	}
	return nil
}

type MetaData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Label         string `protobuf:"bytes,1,opt,name=Label,proto3" json:"Label,omitempty"`
	ContainerName string `protobuf:"bytes,2,opt,name=ContainerName,proto3" json:"ContainerName,omitempty"`
}

func (x *MetaData) Reset() {
	*x = MetaData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_report_report_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetaData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetaData) ProtoMessage() {}

func (x *MetaData) ProtoReflect() protoreflect.Message {
	mi := &file_v1_report_report_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetaData.ProtoReflect.Descriptor instead.
func (*MetaData) Descriptor() ([]byte, []int) {
	return file_v1_report_report_proto_rawDescGZIP(), []int{7}
}

func (x *MetaData) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *MetaData) GetContainerName() string {
	if x != nil {
		return x.ContainerName
	}
	return ""
}

var File_v1_report_report_proto protoreflect.FileDescriptor

var file_v1_report_report_proto_rawDesc = []byte{
	0x0a, 0x16, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x72, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x1a, 0x24, 0x76, 0x31, 0x2f, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x62,
	0x69, 0x6c, 0x69, 0x74, 0x79, 0x2f, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb6, 0x02, 0x0a, 0x0d, 0x52, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x43,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x43,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x4e, 0x61, 0x6d,
	0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x50, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2f, 0x0a, 0x08, 0x4d, 0x65, 0x74,
	0x61, 0x44, 0x61, 0x74, 0x61, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x76, 0x31,
	0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x44, 0x61, 0x74, 0x61,
	0x52, 0x08, 0x4d, 0x65, 0x74, 0x61, 0x44, 0x61, 0x74, 0x61, 0x12, 0x1c, 0x0a, 0x09, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x4f,
	0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x18, 0x08, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x12, 0x20, 0x0a, 0x0b, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x09, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0xaa, 0x01, 0x0a, 0x0e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x43, 0x0a, 0x08, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x08, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x1a, 0x53, 0x0a, 0x0d, 0x43, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2c, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x76,
	0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x44, 0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22,
	0xd0, 0x01, 0x0a, 0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x12,
	0x20, 0x0a, 0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x46, 0x0a, 0x0a, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x4e, 0x61,
	0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x4e,
	0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x1a, 0x57, 0x0a, 0x0f, 0x4e, 0x61, 0x6d,
	0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2e,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e,
	0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x22, 0xe7, 0x01, 0x0a, 0x0d, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65,
	0x44, 0x61, 0x74, 0x61, 0x12, 0x24, 0x0a, 0x0d, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x4e, 0x61, 0x6d,
	0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x51, 0x0a, 0x0d, 0x52, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2b, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x4e, 0x61,
	0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x52, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0d,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x73, 0x1a, 0x5d, 0x0a,
	0x12, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x31, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x44, 0x61, 0x74,
	0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xd7, 0x01, 0x0a,
	0x10, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x22, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x48, 0x0a, 0x09, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x09, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x1a,
	0x55, 0x0a, 0x0e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x2d, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x17, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xb3, 0x01, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x22, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x29, 0x0a, 0x05, 0x4d, 0x44, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13,
	0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x05, 0x4d, 0x44, 0x61, 0x74, 0x61, 0x12, 0x30, 0x0a, 0x07, 0x53, 0x75,
	0x6d, 0x44, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x76, 0x31,
	0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x07, 0x53, 0x75, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x22, 0x8d, 0x03, 0x0a,
	0x0b, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x44, 0x61, 0x74, 0x61, 0x12, 0x4a, 0x0a, 0x0b,
	0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x44, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x28, 0x2e, 0x76, 0x31, 0x2e, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x62, 0x69,
	0x6c, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x79, 0x73, 0x50, 0x72, 0x6f, 0x63, 0x46, 0x69, 0x6c, 0x65,
	0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x44, 0x61, 0x74, 0x61, 0x52, 0x0b, 0x50, 0x72, 0x6f,
	0x63, 0x65, 0x73, 0x73, 0x44, 0x61, 0x74, 0x61, 0x12, 0x44, 0x0a, 0x08, 0x46, 0x69, 0x6c, 0x65,
	0x44, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x76, 0x31, 0x2e,
	0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x79,
	0x73, 0x50, 0x72, 0x6f, 0x63, 0x46, 0x69, 0x6c, 0x65, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79,
	0x44, 0x61, 0x74, 0x61, 0x52, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x50,
	0x0a, 0x11, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x76, 0x31, 0x2e, 0x6f,
	0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x79, 0x73,
	0x4e, 0x77, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x44, 0x61, 0x74, 0x61, 0x52, 0x11, 0x49,
	0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x4e, 0x0a, 0x10, 0x45, 0x67, 0x72, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x76, 0x31, 0x2e,
	0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x79,
	0x73, 0x4e, 0x77, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x44, 0x61, 0x74, 0x61, 0x52, 0x10,
	0x45, 0x67, 0x72, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x4a, 0x0a, 0x0e, 0x42, 0x69, 0x6e, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x76, 0x31, 0x2e, 0x6f, 0x62,
	0x73, 0x65, 0x72, 0x76, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x79, 0x73, 0x4e,
	0x77, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x44, 0x61, 0x74, 0x61, 0x52, 0x0e, 0x42, 0x69,
	0x6e, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x46, 0x0a, 0x08,
	0x4d, 0x65, 0x74, 0x61, 0x44, 0x61, 0x74, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x4c, 0x61, 0x62, 0x65,
	0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x24,
	0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x4e, 0x61, 0x6d, 0x65, 0x32, 0x4a, 0x0a, 0x06, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x40,
	0x0a, 0x09, 0x47, 0x65, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x2e, 0x76, 0x31,
	0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x76, 0x31, 0x2e, 0x72, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x42, 0x5a, 0x40, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61,
	0x63, 0x63, 0x75, 0x6b, 0x6e, 0x6f, 0x78, 0x2f, 0x61, 0x75, 0x74, 0x6f, 0x2d, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x2d, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x73, 0x72,
	0x63, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_report_report_proto_rawDescOnce sync.Once
	file_v1_report_report_proto_rawDescData = file_v1_report_report_proto_rawDesc
)

func file_v1_report_report_proto_rawDescGZIP() []byte {
	file_v1_report_report_proto_rawDescOnce.Do(func() {
		file_v1_report_report_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_report_report_proto_rawDescData)
	})
	return file_v1_report_report_proto_rawDescData
}

var file_v1_report_report_proto_msgTypes = make([]protoimpl.MessageInfo, 12)
var file_v1_report_report_proto_goTypes = []interface{}{
	(*ReportRequest)(nil),    // 0: v1.report.ReportRequest
	(*ReportResponse)(nil),   // 1: v1.report.ReportResponse
	(*ClusterData)(nil),      // 2: v1.report.ClusterData
	(*NamespaceData)(nil),    // 3: v1.report.NamespaceData
	(*ResourceTypeData)(nil), // 4: v1.report.ResourceTypeData
	(*ResourceData)(nil),     // 5: v1.report.ResourceData
	(*SummaryData)(nil),      // 6: v1.report.SummaryData
	(*MetaData)(nil),         // 7: v1.report.MetaData
	nil,                      // 8: v1.report.ReportResponse.ClustersEntry
	nil,                      // 9: v1.report.ClusterData.NamespacesEntry
	nil,                      // 10: v1.report.NamespaceData.ResourceTypesEntry
	nil,                      // 11: v1.report.ResourceTypeData.ResourcesEntry
	(*observability.SysProcFileSummaryData)(nil), // 12: v1.observability.SysProcFileSummaryData
	(*observability.SysNwSummaryData)(nil),       // 13: v1.observability.SysNwSummaryData
}
var file_v1_report_report_proto_depIdxs = []int32{
	7,  // 0: v1.report.ReportRequest.MetaData:type_name -> v1.report.MetaData
	8,  // 1: v1.report.ReportResponse.Clusters:type_name -> v1.report.ReportResponse.ClustersEntry
	9,  // 2: v1.report.ClusterData.Namespaces:type_name -> v1.report.ClusterData.NamespacesEntry
	10, // 3: v1.report.NamespaceData.ResourceTypes:type_name -> v1.report.NamespaceData.ResourceTypesEntry
	11, // 4: v1.report.ResourceTypeData.Resources:type_name -> v1.report.ResourceTypeData.ResourcesEntry
	7,  // 5: v1.report.ResourceData.MData:type_name -> v1.report.MetaData
	6,  // 6: v1.report.ResourceData.SumData:type_name -> v1.report.SummaryData
	12, // 7: v1.report.SummaryData.ProcessData:type_name -> v1.observability.SysProcFileSummaryData
	12, // 8: v1.report.SummaryData.FileData:type_name -> v1.observability.SysProcFileSummaryData
	13, // 9: v1.report.SummaryData.IngressConnection:type_name -> v1.observability.SysNwSummaryData
	13, // 10: v1.report.SummaryData.EgressConnection:type_name -> v1.observability.SysNwSummaryData
	13, // 11: v1.report.SummaryData.BindConnection:type_name -> v1.observability.SysNwSummaryData
	2,  // 12: v1.report.ReportResponse.ClustersEntry.value:type_name -> v1.report.ClusterData
	3,  // 13: v1.report.ClusterData.NamespacesEntry.value:type_name -> v1.report.NamespaceData
	4,  // 14: v1.report.NamespaceData.ResourceTypesEntry.value:type_name -> v1.report.ResourceTypeData
	5,  // 15: v1.report.ResourceTypeData.ResourcesEntry.value:type_name -> v1.report.ResourceData
	0,  // 16: v1.report.Report.GetReport:input_type -> v1.report.ReportRequest
	1,  // 17: v1.report.Report.GetReport:output_type -> v1.report.ReportResponse
	17, // [17:18] is the sub-list for method output_type
	16, // [16:17] is the sub-list for method input_type
	16, // [16:16] is the sub-list for extension type_name
	16, // [16:16] is the sub-list for extension extendee
	0,  // [0:16] is the sub-list for field type_name
}

func init() { file_v1_report_report_proto_init() }
func file_v1_report_report_proto_init() {
	if File_v1_report_report_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_v1_report_report_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReportRequest); i {
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
		file_v1_report_report_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReportResponse); i {
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
		file_v1_report_report_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClusterData); i {
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
		file_v1_report_report_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NamespaceData); i {
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
		file_v1_report_report_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceTypeData); i {
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
		file_v1_report_report_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceData); i {
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
		file_v1_report_report_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SummaryData); i {
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
		file_v1_report_report_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetaData); i {
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
			RawDescriptor: file_v1_report_report_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   12,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_v1_report_report_proto_goTypes,
		DependencyIndexes: file_v1_report_report_proto_depIdxs,
		MessageInfos:      file_v1_report_report_proto_msgTypes,
	}.Build()
	File_v1_report_report_proto = out.File
	file_v1_report_report_proto_rawDesc = nil
	file_v1_report_report_proto_goTypes = nil
	file_v1_report_report_proto_depIdxs = nil
}
