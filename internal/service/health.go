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

type HealthService struct {
	uc *vproxy.VaultUsercase
}

func NewHealthService(uc *vproxy.VaultUsercase) *HealthService {
	return &HealthService{uc: uc}
}

func (s *HealthService) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthReply, error) {
	standBy := false
	vaultStatus := s.uc.Health()

	if vaultStatus {
		standBy = true
	}

	return &pb.HealthReply{
		StandBy: standBy,
		Vault:   vaultStatus,
	}, nil
}
