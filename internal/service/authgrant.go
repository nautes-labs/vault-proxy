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

type AuthGrantService struct {
	uc *vproxy.VaultUsercase
}

func NewAuthGrantService(uc *vproxy.VaultUsercase) *AuthGrantService {
	return &AuthGrantService{uc: uc}
}
func (s *AuthGrantService) GrantAuthroleGitPolicy(ctx context.Context, req *pb.AuthroleGitPolicyRequest) (*pb.GrantAuthrolePolicyReply, error) {

	err := s.uc.GrantPermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.GrantAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) RevokeAuthroleGitPolicy(ctx context.Context, req *pb.AuthroleGitPolicyRequest) (*pb.RevokeAuthrolePolicyReply, error) {
	err := s.uc.RevokePermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.RevokeAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) GrantAuthroleRepoPolicy(ctx context.Context, req *pb.AuthroleRepoPolicyRequest) (*pb.GrantAuthrolePolicyReply, error) {
	err := s.uc.GrantPermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.GrantAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) RevokeAuthroleRepoPolicy(ctx context.Context, req *pb.AuthroleRepoPolicyRequest) (*pb.RevokeAuthrolePolicyReply, error) {
	err := s.uc.RevokePermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.RevokeAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) GrantAuthroleClusterPolicy(ctx context.Context, req *pb.AuthroleClusterPolicyRequest) (*pb.GrantAuthrolePolicyReply, error) {
	err := s.uc.GrantPermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.GrantAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) RevokeAuthroleClusterPolicy(ctx context.Context, req *pb.AuthroleClusterPolicyRequest) (*pb.RevokeAuthrolePolicyReply, error) {
	err := s.uc.RevokePermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.RevokeAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) GrantAuthroleTenantGitPolicy(ctx context.Context, req *pb.AuthroleTenantGitPolicyRequest) (*pb.GrantAuthrolePolicyReply, error) {
	err := s.uc.GrantPermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.GrantAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) RevokeAuthroleTenantGitPolicy(ctx context.Context, req *pb.AuthroleTenantGitPolicyRequest) (*pb.RevokeAuthrolePolicyReply, error) {
	err := s.uc.RevokePermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.RevokeAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) GrantAuthroleTenantRepoPolicy(ctx context.Context, req *pb.AuthroleTenantRepoPolicyRequest) (*pb.GrantAuthrolePolicyReply, error) {
	err := s.uc.GrantPermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.GrantAuthrolePolicyReply{}, nil
}
func (s *AuthGrantService) RevokeAuthroleTenantRepoPolicy(ctx context.Context, req *pb.AuthroleTenantRepoPolicyRequest) (*pb.RevokeAuthrolePolicyReply, error) {
	err := s.uc.RevokePermision(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.RevokeAuthrolePolicyReply{}, nil
}
