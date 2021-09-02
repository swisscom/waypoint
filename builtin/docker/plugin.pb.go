// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.8
// source: waypoint/builtin/docker/plugin.proto

package docker

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Image is the artifact type for the registry.
type Image struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Image string `protobuf:"bytes,1,opt,name=image,proto3" json:"image,omitempty"`
	Tag   string `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	// location is where this image is currently. This can be used to
	// determine if the image is pulled or not based on this proto rather
	// than environment inspection.
	//
	// If this is not set, it will be assumed that the image is in a local
	// Docker daemon registry for backwards compatiblity reasons.
	//
	// Types that are assignable to Location:
	//	*Image_Registry
	//	*Image_Docker
	//	*Image_Img
	Location isImage_Location `protobuf_oneof:"location"`
}

func (x *Image) Reset() {
	*x = Image{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Image) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Image) ProtoMessage() {}

func (x *Image) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Image.ProtoReflect.Descriptor instead.
func (*Image) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{0}
}

func (x *Image) GetImage() string {
	if x != nil {
		return x.Image
	}
	return ""
}

func (x *Image) GetTag() string {
	if x != nil {
		return x.Tag
	}
	return ""
}

func (m *Image) GetLocation() isImage_Location {
	if m != nil {
		return m.Location
	}
	return nil
}

func (x *Image) GetRegistry() *emptypb.Empty {
	if x, ok := x.GetLocation().(*Image_Registry); ok {
		return x.Registry
	}
	return nil
}

func (x *Image) GetDocker() *emptypb.Empty {
	if x, ok := x.GetLocation().(*Image_Docker); ok {
		return x.Docker
	}
	return nil
}

func (x *Image) GetImg() *emptypb.Empty {
	if x, ok := x.GetLocation().(*Image_Img); ok {
		return x.Img
	}
	return nil
}

type isImage_Location interface {
	isImage_Location()
}

type Image_Registry struct {
	// registry is set if the image is in a remote registry. This value
	// might mean the image is local, too, but we never formally "pulled"
	// it so we aren't sure. The image should be treated as remote.
	Registry *emptypb.Empty `protobuf:"bytes,3,opt,name=registry,proto3,oneof"`
}

type Image_Docker struct {
	// docker is set if the image is in a local Docker daemon registry.
	Docker *emptypb.Empty `protobuf:"bytes,4,opt,name=docker,proto3,oneof"`
}

type Image_Img struct {
	// img is set if the image is in a local img content store directory.
	// img: https://github.com/genuinetools/img
	Img *emptypb.Empty `protobuf:"bytes,5,opt,name=img,proto3,oneof"`
}

func (*Image_Registry) isImage_Location() {}

func (*Image_Docker) isImage_Location() {}

func (*Image_Img) isImage_Location() {}

type Deployment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id            string     `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name          string     `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Container     string     `protobuf:"bytes,3,opt,name=container,proto3" json:"container,omitempty"`
	ResourceState *anypb.Any `protobuf:"bytes,4,opt,name=resource_state,json=resourceState,proto3" json:"resource_state,omitempty"`
}

func (x *Deployment) Reset() {
	*x = Deployment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Deployment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Deployment) ProtoMessage() {}

func (x *Deployment) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Deployment.ProtoReflect.Descriptor instead.
func (*Deployment) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{1}
}

func (x *Deployment) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Deployment) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Deployment) GetContainer() string {
	if x != nil {
		return x.Container
	}
	return ""
}

func (x *Deployment) GetResourceState() *anypb.Any {
	if x != nil {
		return x.ResourceState
	}
	return nil
}

type Release struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Url string `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
}

func (x *Release) Reset() {
	*x = Release{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Release) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Release) ProtoMessage() {}

func (x *Release) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Release.ProtoReflect.Descriptor instead.
func (*Release) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{2}
}

func (x *Release) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

// Resource contains the internal resource states.
type Resource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Resource) Reset() {
	*x = Resource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource) ProtoMessage() {}

func (x *Resource) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource.ProtoReflect.Descriptor instead.
func (*Resource) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{3}
}

type TaskInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *TaskInfo) Reset() {
	*x = TaskInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskInfo) ProtoMessage() {}

func (x *TaskInfo) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskInfo.ProtoReflect.Descriptor instead.
func (*TaskInfo) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{4}
}

func (x *TaskInfo) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type AccessInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// image is the OCI compatible descriptor for the location of the image. Typically it
	// is in the form `repo/name`, where repo is a host name (perhaps with a port), and
	// name may also contain / use to identify subdivision on the host.
	Image string `protobuf:"bytes,1,opt,name=image,proto3" json:"image,omitempty"`
	// tag is the OCI compatible tag that the resulting data will be stored at within
	// the repository defined by image.
	Tag string `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	// auth indicates how to authenticate with the repository defined by image.
	//
	// Types that are assignable to Auth:
	//	*AccessInfo_Header
	//	*AccessInfo_Encoded
	//	*AccessInfo_UserPass_
	Auth isAccessInfo_Auth `protobuf_oneof:"auth"`
	// insecure indicates if the repository defined by image should be access via http or https.
	Insecure bool `protobuf:"varint,5,opt,name=insecure,proto3" json:"insecure,omitempty"`
}

func (x *AccessInfo) Reset() {
	*x = AccessInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessInfo) ProtoMessage() {}

func (x *AccessInfo) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessInfo.ProtoReflect.Descriptor instead.
func (*AccessInfo) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{5}
}

func (x *AccessInfo) GetImage() string {
	if x != nil {
		return x.Image
	}
	return ""
}

func (x *AccessInfo) GetTag() string {
	if x != nil {
		return x.Tag
	}
	return ""
}

func (m *AccessInfo) GetAuth() isAccessInfo_Auth {
	if m != nil {
		return m.Auth
	}
	return nil
}

func (x *AccessInfo) GetHeader() string {
	if x, ok := x.GetAuth().(*AccessInfo_Header); ok {
		return x.Header
	}
	return ""
}

func (x *AccessInfo) GetEncoded() string {
	if x, ok := x.GetAuth().(*AccessInfo_Encoded); ok {
		return x.Encoded
	}
	return ""
}

func (x *AccessInfo) GetUserPass() *AccessInfo_UserPass {
	if x, ok := x.GetAuth().(*AccessInfo_UserPass_); ok {
		return x.UserPass
	}
	return nil
}

func (x *AccessInfo) GetInsecure() bool {
	if x != nil {
		return x.Insecure
	}
	return false
}

type isAccessInfo_Auth interface {
	isAccessInfo_Auth()
}

type AccessInfo_Header struct {
	// header is the value of the Authentication header that is sent to the repository.
	// This allows for repositories that use bearer tokens or other sorts of authentication.
	Header string `protobuf:"bytes,3,opt,name=header,proto3,oneof"`
}

type AccessInfo_Encoded struct {
	// encoded is the docker standard encoded authentication data. This is base64 encoded
	// json that contains username and passwword fields that are used for authentication.
	Encoded string `protobuf:"bytes,4,opt,name=encoded,proto3,oneof"`
}

type AccessInfo_UserPass_ struct {
	// user_pass specifies a username and password to use to authenticate with the registry.
	// The registry plugin will transform this information to the proper format as needed.
	UserPass *AccessInfo_UserPass `protobuf:"bytes,6,opt,name=user_pass,json=userPass,proto3,oneof"`
}

func (*AccessInfo_Header) isAccessInfo_Auth() {}

func (*AccessInfo_Encoded) isAccessInfo_Auth() {}

func (*AccessInfo_UserPass_) isAccessInfo_Auth() {}

type Resource_Network struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *Resource_Network) Reset() {
	*x = Resource_Network{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource_Network) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource_Network) ProtoMessage() {}

func (x *Resource_Network) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource_Network.ProtoReflect.Descriptor instead.
func (*Resource_Network) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{3, 0}
}

func (x *Resource_Network) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type Resource_Container struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id   string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *Resource_Container) Reset() {
	*x = Resource_Container{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource_Container) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource_Container) ProtoMessage() {}

func (x *Resource_Container) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource_Container.ProtoReflect.Descriptor instead.
func (*Resource_Container) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{3, 1}
}

func (x *Resource_Container) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Resource_Container) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type AccessInfo_UserPass struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The username to authenticate against the registry with
	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	// The password assocated with the above username
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *AccessInfo_UserPass) Reset() {
	*x = AccessInfo_UserPass{}
	if protoimpl.UnsafeEnabled {
		mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessInfo_UserPass) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessInfo_UserPass) ProtoMessage() {}

func (x *AccessInfo_UserPass) ProtoReflect() protoreflect.Message {
	mi := &file_waypoint_builtin_docker_plugin_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessInfo_UserPass.ProtoReflect.Descriptor instead.
func (*AccessInfo_UserPass) Descriptor() ([]byte, []int) {
	return file_waypoint_builtin_docker_plugin_proto_rawDescGZIP(), []int{5, 0}
}

func (x *AccessInfo_UserPass) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *AccessInfo_UserPass) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

var File_waypoint_builtin_docker_plugin_proto protoreflect.FileDescriptor

var file_waypoint_builtin_docker_plugin_proto_rawDesc = []byte{
	0x0a, 0x24, 0x77, 0x61, 0x79, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2f, 0x62, 0x75, 0x69, 0x6c, 0x74,
	0x69, 0x6e, 0x2f, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x1a, 0x19,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xcf, 0x01, 0x0a, 0x05, 0x49, 0x6d, 0x61, 0x67, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x61, 0x67, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x74, 0x61, 0x67, 0x12, 0x34, 0x0a, 0x08, 0x72, 0x65, 0x67, 0x69,
	0x73, 0x74, 0x72, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x48, 0x00, 0x52, 0x08, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x12, 0x30,
	0x0a, 0x06, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x48, 0x00, 0x52, 0x06, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72,
	0x12, 0x2a, 0x0a, 0x03, 0x69, 0x6d, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x48, 0x00, 0x52, 0x03, 0x69, 0x6d, 0x67, 0x42, 0x0a, 0x0a, 0x08,
	0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x8b, 0x01, 0x0a, 0x0a, 0x44, 0x65, 0x70,
	0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x63,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x3b, 0x0a, 0x0e, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x0d, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x22, 0x1b, 0x0a, 0x07, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73,
	0x65, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x75, 0x72, 0x6c, 0x22, 0x5a, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x1a,
	0x1d, 0x0a, 0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x1a, 0x2f,
	0x0a, 0x09, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22,
	0x1a, 0x0a, 0x08, 0x54, 0x61, 0x73, 0x6b, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x8e, 0x02, 0x0a, 0x0a,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6d,
	0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65,
	0x12, 0x10, 0x0a, 0x03, 0x74, 0x61, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x74,
	0x61, 0x67, 0x12, 0x18, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x00, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1a, 0x0a, 0x07,
	0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x07, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x12, 0x3a, 0x0a, 0x09, 0x75, 0x73, 0x65, 0x72,
	0x5f, 0x70, 0x61, 0x73, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x64, 0x6f,
	0x63, 0x6b, 0x65, 0x72, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x55, 0x73, 0x65, 0x72, 0x50, 0x61, 0x73, 0x73, 0x48, 0x00, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72,
	0x50, 0x61, 0x73, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65,
	0x1a, 0x42, 0x0a, 0x08, 0x55, 0x73, 0x65, 0x72, 0x50, 0x61, 0x73, 0x73, 0x12, 0x1a, 0x0a, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x42, 0x06, 0x0a, 0x04, 0x61, 0x75, 0x74, 0x68, 0x42, 0x19, 0x5a, 0x17,
	0x77, 0x61, 0x79, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2f, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e,
	0x2f, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_waypoint_builtin_docker_plugin_proto_rawDescOnce sync.Once
	file_waypoint_builtin_docker_plugin_proto_rawDescData = file_waypoint_builtin_docker_plugin_proto_rawDesc
)

func file_waypoint_builtin_docker_plugin_proto_rawDescGZIP() []byte {
	file_waypoint_builtin_docker_plugin_proto_rawDescOnce.Do(func() {
		file_waypoint_builtin_docker_plugin_proto_rawDescData = protoimpl.X.CompressGZIP(file_waypoint_builtin_docker_plugin_proto_rawDescData)
	})
	return file_waypoint_builtin_docker_plugin_proto_rawDescData
}

var file_waypoint_builtin_docker_plugin_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_waypoint_builtin_docker_plugin_proto_goTypes = []interface{}{
	(*Image)(nil),               // 0: docker.Image
	(*Deployment)(nil),          // 1: docker.Deployment
	(*Release)(nil),             // 2: docker.Release
	(*Resource)(nil),            // 3: docker.Resource
	(*TaskInfo)(nil),            // 4: docker.TaskInfo
	(*AccessInfo)(nil),          // 5: docker.AccessInfo
	(*Resource_Network)(nil),    // 6: docker.Resource.Network
	(*Resource_Container)(nil),  // 7: docker.Resource.Container
	(*AccessInfo_UserPass)(nil), // 8: docker.AccessInfo.UserPass
	(*emptypb.Empty)(nil),       // 9: google.protobuf.Empty
	(*anypb.Any)(nil),           // 10: google.protobuf.Any
}
var file_waypoint_builtin_docker_plugin_proto_depIdxs = []int32{
	9,  // 0: docker.Image.registry:type_name -> google.protobuf.Empty
	9,  // 1: docker.Image.docker:type_name -> google.protobuf.Empty
	9,  // 2: docker.Image.img:type_name -> google.protobuf.Empty
	10, // 3: docker.Deployment.resource_state:type_name -> google.protobuf.Any
	8,  // 4: docker.AccessInfo.user_pass:type_name -> docker.AccessInfo.UserPass
	5,  // [5:5] is the sub-list for method output_type
	5,  // [5:5] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_waypoint_builtin_docker_plugin_proto_init() }
func file_waypoint_builtin_docker_plugin_proto_init() {
	if File_waypoint_builtin_docker_plugin_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_waypoint_builtin_docker_plugin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Image); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Deployment); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Release); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskInfo); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessInfo); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource_Network); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource_Container); i {
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
		file_waypoint_builtin_docker_plugin_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessInfo_UserPass); i {
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
	file_waypoint_builtin_docker_plugin_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Image_Registry)(nil),
		(*Image_Docker)(nil),
		(*Image_Img)(nil),
	}
	file_waypoint_builtin_docker_plugin_proto_msgTypes[5].OneofWrappers = []interface{}{
		(*AccessInfo_Header)(nil),
		(*AccessInfo_Encoded)(nil),
		(*AccessInfo_UserPass_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_waypoint_builtin_docker_plugin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_waypoint_builtin_docker_plugin_proto_goTypes,
		DependencyIndexes: file_waypoint_builtin_docker_plugin_proto_depIdxs,
		MessageInfos:      file_waypoint_builtin_docker_plugin_proto_msgTypes,
	}.Build()
	File_waypoint_builtin_docker_plugin_proto = out.File
	file_waypoint_builtin_docker_plugin_proto_rawDesc = nil
	file_waypoint_builtin_docker_plugin_proto_goTypes = nil
	file_waypoint_builtin_docker_plugin_proto_depIdxs = nil
}
