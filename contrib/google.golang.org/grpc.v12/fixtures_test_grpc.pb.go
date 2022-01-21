// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package grpc

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// FixtureClient is the client API for Fixture service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FixtureClient interface {
	Ping(ctx context.Context, in *FixtureRequest, opts ...grpc.CallOption) (*FixtureReply, error)
}

type fixtureClient struct {
	cc grpc.ClientConnInterface
}

func NewFixtureClient(cc grpc.ClientConnInterface) FixtureClient {
	return &fixtureClient{cc}
}

func (c *fixtureClient) Ping(ctx context.Context, in *FixtureRequest, opts ...grpc.CallOption) (*FixtureReply, error) {
	out := new(FixtureReply)
	err := c.cc.Invoke(ctx, "/grpc.Fixture/Ping", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FixtureServer is the server API for Fixture service.
// All implementations must embed UnimplementedFixtureServer
// for forward compatibility
type FixtureServer interface {
	Ping(context.Context, *FixtureRequest) (*FixtureReply, error)
	mustEmbedUnimplementedFixtureServer()
}

// UnimplementedFixtureServer must be embedded to have forward compatible implementations.
type UnimplementedFixtureServer struct {
}

func (UnimplementedFixtureServer) Ping(context.Context, *FixtureRequest) (*FixtureReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ping not implemented")
}
func (UnimplementedFixtureServer) mustEmbedUnimplementedFixtureServer() {}

// UnsafeFixtureServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FixtureServer will
// result in compilation errors.
type UnsafeFixtureServer interface {
	mustEmbedUnimplementedFixtureServer()
}

func RegisterFixtureServer(s grpc.ServiceRegistrar, srv FixtureServer) {
	s.RegisterService(&Fixture_ServiceDesc, srv)
}

func _Fixture_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FixtureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FixtureServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.Fixture/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FixtureServer).Ping(ctx, req.(*FixtureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Fixture_ServiceDesc is the grpc.ServiceDesc for Fixture service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Fixture_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.Fixture",
	HandlerType: (*FixtureServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _Fixture_Ping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "fixtures_test.proto",
}
