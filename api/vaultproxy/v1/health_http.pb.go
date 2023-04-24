// Code generated by protoc-gen-go-http. DO NOT EDIT.
// versions:
// - protoc-gen-go-http v2.6.1
// - protoc             v3.21.5
// source: api/vaultproxy/v1/health.proto

package v1

import (
	context "context"
	http "github.com/go-kratos/kratos/v2/transport/http"
	binding "github.com/go-kratos/kratos/v2/transport/http/binding"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the kratos package it is being compiled against.
var _ = new(context.Context)
var _ = binding.EncodeURL

const _ = http.SupportPackageIsVersion1

const OperationHealthHealth = "/api.vaultproxy.v1.Health/Health"

type HealthHTTPServer interface {
	Health(context.Context, *HealthRequest) (*HealthReply, error)
}

func RegisterHealthHTTPServer(s *http.Server, srv HealthHTTPServer) {
	r := s.Route("/")
	r.GET("/health", _Health_Health0_HTTP_Handler(srv))
}

func _Health_Health0_HTTP_Handler(srv HealthHTTPServer) func(ctx http.Context) error {
	return func(ctx http.Context) error {
		var in HealthRequest
		if err := ctx.BindQuery(&in); err != nil {
			return err
		}
		http.SetOperation(ctx, OperationHealthHealth)
		h := ctx.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.Health(ctx, req.(*HealthRequest))
		})
		out, err := h(ctx, &in)
		if err != nil {
			return err
		}
		reply := out.(*HealthReply)
		return ctx.Result(200, reply)
	}
}

type HealthHTTPClient interface {
	Health(ctx context.Context, req *HealthRequest, opts ...http.CallOption) (rsp *HealthReply, err error)
}

type HealthHTTPClientImpl struct {
	cc *http.Client
}

func NewHealthHTTPClient(client *http.Client) HealthHTTPClient {
	return &HealthHTTPClientImpl{client}
}

func (c *HealthHTTPClientImpl) Health(ctx context.Context, in *HealthRequest, opts ...http.CallOption) (*HealthReply, error) {
	var out HealthReply
	pattern := "/health"
	path := binding.EncodeURL(pattern, in, true)
	opts = append(opts, http.Operation(OperationHealthHealth))
	opts = append(opts, http.PathTemplate(pattern))
	err := c.cc.Invoke(ctx, "GET", path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, err
}
