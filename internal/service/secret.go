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

type SecretService struct {
	uc *vproxy.VaultUsercase
}

func NewSecretService(uc *vproxy.VaultUsercase) *SecretService {
	return &SecretService{uc: uc}
}

func (s *SecretService) CreateGit(ctx context.Context, req *pb.GitRequest) (*pb.CreateGitReply, error) {
	sec, err := s.uc.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateGitReply{
		SecretName:    sec.SecretName,
		SecretPath:    sec.SecretPath,
		SecretVersion: int32(sec.SecretVersion),
	}, nil
}
func (s *SecretService) DeleteGit(ctx context.Context, req *pb.GitRequest) (*pb.DeleteGitReply, error) {
	err := s.uc.DeleteSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteGitReply{}, nil
}
func (s *SecretService) CreatePki(ctx context.Context, req *pb.PkiRequest) (*pb.CreatePkiReply, error) {
	return &pb.CreatePkiReply{}, nil
}
func (s *SecretService) DeletePki(ctx context.Context, req *pb.PkiRequest) (*pb.DeletePkiReply, error) {
	return &pb.DeletePkiReply{}, nil
}
func (s *SecretService) CreateRepo(ctx context.Context, req *pb.RepoRequest) (*pb.CreateRepoReply, error) {
	sec, err := s.uc.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateRepoReply{
		SecretName:    sec.SecretName,
		SecretPath:    sec.SecretPath,
		SecretVersion: int32(sec.SecretVersion),
	}, nil
}
func (s *SecretService) DeleteRepo(ctx context.Context, req *pb.RepoRequest) (*pb.DeleteRepoReply, error) {
	err := s.uc.DeleteSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteRepoReply{}, nil
}
func (s *SecretService) CreteTenantGit(ctx context.Context, req *pb.TenantGitRequest) (*pb.CreateTenantGitReply, error) {
	sec, err := s.uc.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateTenantGitReply{
		SecretName:    sec.SecretName,
		SecretPath:    sec.SecretPath,
		SecretVersion: int32(sec.SecretVersion),
	}, nil
}
func (s *SecretService) DeleteTenantGit(ctx context.Context, req *pb.TenantGitRequest) (*pb.DeleteTenantGitReply, error) {
	err := s.uc.DeleteSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteTenantGitReply{}, nil
}
func (s *SecretService) CreateTenantRepo(ctx context.Context, req *pb.TenantRepoRequest) (*pb.CreateTenantRepoReply, error) {
	sec, err := s.uc.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateTenantRepoReply{
		SecretName:    sec.SecretName,
		SecretPath:    sec.SecretPath,
		SecretVersion: int32(sec.SecretVersion),
	}, nil
}
func (s *SecretService) DeleteTenantRepo(ctx context.Context, req *pb.TenantRepoRequest) (*pb.DeleteTenantRepoReply, error) {
	err := s.uc.DeleteSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteTenantRepoReply{}, nil
}
func (s *SecretService) CreateCluster(ctx context.Context, req *pb.ClusterRequest) (*pb.CreateClusterReply, error) {
	sec, err := s.uc.CreateSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.CreateClusterReply{
		SecretName:    sec.SecretName,
		SecretPath:    sec.SecretPath,
		SecretVersion: int32(sec.SecretVersion),
	}, nil
}
func (s *SecretService) DeleteCluster(ctx context.Context, req *pb.ClusterRequest) (*pb.DeleteClusterReply, error) {
	err := s.uc.DeleteSecret(ctx, req)
	if err != nil {
		return nil, err
	}
	return &pb.DeleteClusterReply{}, nil
}
