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
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"

	"github.com/nautes-labs/vault-proxy/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
	vault "github.com/hashicorp/vault/api"
	approleauth "github.com/hashicorp/vault/api/auth/approle"
)

type VaultClient struct {
	Client *vault.Client
	log    *log.Helper
}

func NewVaultClient(c *conf.Data, logger log.Logger) VaultClientInterface {
	helper := log.NewHelper(logger)
	if c.Vault == nil {
		helper.Fatal("can not find data setting in config sources!")
		return nil
	}
	config := vault.DefaultConfig()
	config.Address = c.Vault.Addr

	if c.Vault.Cert != nil && c.Vault.Cert.CaCert != "" {
		ca := c.Vault.Cert.CaCert
		caCert, err := ioutil.ReadFile(ca)
		if err != nil {
			helper.Fatal(err)
			return nil
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		config.HttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
	}

	client, err := vault.NewClient(config)
	if err != nil {
		helper.Fatalf("initialize vault client failed: %v", err)
		return nil
	}

	if c.Vault.Token != "" {
		client.SetToken(c.Vault.Token)
		return &VaultClient{Client: client, log: helper}
	}

	appRoleAuth, err := approleauth.NewAppRoleAuth(
		c.Vault.RoleID,
		&approleauth.SecretID{FromString: c.Vault.SecretID},
		approleauth.WithMountPath(c.Vault.AuthPath),
	)
	if err != nil {
		helper.Fatalf("create auth info failed: %v", err)
		return nil
	}

	_, err = client.Auth().Login(context.TODO(), appRoleAuth)
	if err != nil {
		helper.Fatalf("login vault failed: %v", err)
		return nil
	}

	return &VaultClient{Client: client, log: helper}
}

func (vc *VaultClient) GetSecret(ctx context.Context, secretname, path string) (*vault.KVSecret, error) {
	kv, err := vc.Client.KVv2(secretname).Get(ctx, path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return nil, err
	}
	vc.log.WithContext(ctx).Infof("get secret %s successed", path)
	return kv, nil
}

func (vc *VaultClient) CreateSecret(ctx context.Context, secretName string, path string, data map[string]interface{}) (*vault.KVSecret, error) {
	kv, err := vc.Client.KVv2(secretName).Put(ctx, path, data)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return nil, err
	}
	vc.log.WithContext(ctx).Infof("create secret %s successed", path)
	return kv, nil
}

func (vc *VaultClient) DeleteSecret(ctx context.Context, secretName string, path string) error {
	err := vc.Client.KVv2(secretName).DeleteMetadata(ctx, path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return err
	}
	vc.log.WithContext(ctx).Infof("delete secret %s successed", path)
	return nil
}

func (vc *VaultClient) RollBackSecret(ctx context.Context, secretName string, path string, toVersion int) error {
	_, err := vc.Client.KVv2(secretName).Rollback(ctx, path, toVersion)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return err
	}
	vc.log.WithContext(ctx).Infof("roll back secret %s successed", path)
	return nil
}

func (vc *VaultClient) GetSecretVersionList(ctx context.Context, secretName string, path string) ([]vault.KVVersionMetadata, error) {
	secretVersionList, err := vc.Client.KVv2(secretName).GetVersionsAsList(ctx, path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return nil, err
	}
	return secretVersionList, nil
}

func (vc *VaultClient) GetPolicy(ctx context.Context, path string) (string, error) {
	policyData, err := vc.Client.Sys().GetPolicy(path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return "", err
	}
	vc.log.WithContext(ctx).Infof("get policy %s", path)
	return policyData, err
}

func (vc *VaultClient) CreatePolicy(ctx context.Context, path string, policy string) error {
	err := vc.Client.Sys().PutPolicy(path, policy)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return err
	}
	vc.log.WithContext(ctx).Infof("create secret policy %s successed", path)
	return nil
}

func (vc *VaultClient) DeletePolicy(ctx context.Context, path string) error {
	err := vc.Client.Sys().DeletePolicy(path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return err
	}
	vc.log.WithContext(ctx).Infof("delete secret policy %s successed", path)
	return nil
}

func (vc *VaultClient) Read(ctx context.Context, path string) (*vault.Secret, error) {
	sec, err := vc.Client.Logical().Read(path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return nil, err
	}
	vc.log.WithContext(ctx).Debugf("request %s successed", path)
	return sec, nil
}

func (vc *VaultClient) Write(ctx context.Context, path string, data map[string]interface{}) (*vault.Secret, error) {
	sec, err := vc.Client.Logical().Write(path, data)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return nil, err
	}
	vc.log.WithContext(ctx).Infof("write %s successed", path)
	return sec, nil
}

func (vc *VaultClient) Delete(ctx context.Context, path string) (*vault.Secret, error) {
	sec, err := vc.Client.Logical().Delete(path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return nil, err
	}
	return sec, nil
}

func (vc *VaultClient) EnableAuth(ctx context.Context, path string, authOptions *vault.MountInput) error {
	err := vc.Client.Sys().EnableAuthWithOptionsWithContext(ctx, path, authOptions)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return err
	}
	return nil
}

func (vc *VaultClient) DisableAuth(ctx context.Context, path string) error {
	err := vc.Client.Sys().DisableAuthWithContext(ctx, path)
	if err != nil {
		vc.log.WithContext(ctx).Error(err)
		return err
	}
	return nil
}

func (vc *VaultClient) Health() bool {
	health, err := vc.Client.Sys().Health()
	if err != nil {
		vc.log.Error(err)
		return false
	}
	if health.Initialized != true && health.Sealed != false {
		vc.log.Error("vault is not initialized or unsealed")
		return false
	}
	return true
}
