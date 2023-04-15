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

package service

import (
	"context"

	pb "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	vproxy "github.com/nautes-labs/vault-proxy/internal/biz/vaultproxy"
)

type AuthService struct {
	uc *vproxy.VaultUsercase
}

func NewAuthService(uc *vproxy.VaultUsercase) *AuthService {
	return &AuthService{uc: uc}
}

func (s *AuthService) CreateAuth(ctx context.Context, req *pb.AuthRequest) (*pb.CreateAuthReply, error) {
	err := s.uc.EnableAuth(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateAuthReply{}, nil
}
func (s *AuthService) DeleteAuth(ctx context.Context, req *pb.AuthRequest) (*pb.DeleteAuthReply, error) {
	err := s.uc.DisableAuth(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteAuthReply{}, nil
}
func (s *AuthService) CreateAuthrole(ctx context.Context, req *pb.AuthroleRequest) (*pb.CreateAuthroleReply, error) {
	err := s.uc.CreateRole(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateAuthroleReply{}, nil
}
func (s *AuthService) DeleteAuthrole(ctx context.Context, req *pb.AuthroleRequest) (*pb.DeleteAuthroleReply, error) {
	err := s.uc.DeleteRole(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteAuthroleReply{}, nil
}
