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

package data

import (
	"context"

	"github.com/nautes-labs/vault-proxy/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
	vault "github.com/hashicorp/vault/api"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewVaultClient)

// Data .
type Data struct {
}

// NewData .
func NewData(_ *conf.Data, logger log.Logger) (*Data, func(), error) {
	cleanup := func() {
		log.NewHelper(logger).Info("closing the data resources")
	}
	return &Data{}, cleanup, nil
}

type VaultClientInterface interface {
	CreateSecret(ctx context.Context, secretName string, path string, data map[string]interface{}) (*vault.KVSecret, error)
	GetSecret(ctx context.Context, secretName, path string) (*vault.KVSecret, error)
	DeleteSecret(ctx context.Context, secretName string, path string) error
	RollBackSecret(ctx context.Context, secretName string, path string, toVersion int) error
	GetSecretVersionList(ctx context.Context, secretName string, path string) ([]vault.KVVersionMetadata, error)
	CreatePolicy(ctx context.Context, path string, policy string) error
	GetPolicy(ctx context.Context, path string) (string, error)
	DeletePolicy(ctx context.Context, path string) error
	Read(ctx context.Context, path string) (*vault.Secret, error)
	Write(ctx context.Context, path string, data map[string]interface{}) (*vault.Secret, error)
	Delete(ctx context.Context, path string) (*vault.Secret, error)
	EnableAuth(ctx context.Context, path string, authOptions *vault.MountInput) error
	DisableAuth(ctx context.Context, path string) error
	Health() bool
}
