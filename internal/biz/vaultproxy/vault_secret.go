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

package vaultproxy

import (
	"context"
	"fmt"

	pb "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
)

type SecretData struct {
	SecretName    string
	SecretPath    string
	SecretVersion int
}

func (uc *VaultUsercase) CreateSecret(ctx context.Context, req pb.SecRequest) (*SecretData, error) {
	secret, err := req.ConvertRequest()
	if err != nil {
		return nil, pb.ErrorInputArgError("convert to secret failed: %s", err)
	}
	if !verifySecret(secret) {
		return nil, errorSecretVerifyFailed
	}
	secretName := secret.SecretName
	secretPath := secret.SecretPath
	data := secret.SecretData
	policyPath := secret.PolicyName
	policyData := secret.PolicyData

	kv, err := uc.client.CreateSecret(ctx, secretName, secretPath, data)
	if err != nil {
		return nil, pb.ErrorInputArgError("create secret failed: %s", err)
	}
	uc.log.WithContext(ctx).Infof("start to create secret %s at sub path %s", secretName, secretPath)

	err = uc.client.CreatePolicy(ctx, policyPath, policyData)
	// If create policy failed, try to rollback secret to the last version
	// If rollback failed, the policy will be removed
	if err != nil {
		rollbackError := uc.revokeToPreVersion(ctx, secretName, secretPath)
		return nil, pb.ErrorInputArgError("create policy %s failed, try to rollback secret %s at sub path %s: %s", policyPath, secretName, secretPath, fmt.Errorf("%v: %s", err, rollbackError))
	}

	return &SecretData{
		SecretName:    secretName,
		SecretPath:    secretPath,
		SecretVersion: kv.VersionMetadata.Version,
	}, nil
}

func (uc *VaultUsercase) revokeToPreVersion(ctx context.Context, secretName, secretPath string) error {
	versionList, err := uc.client.GetSecretVersionList(ctx, secretName, secretPath)
	if err != nil {
		return fmt.Errorf("get %s last version list failed: %s", secretName, err)
	}
	index := len(versionList)
	if index > 1 {
		err := uc.client.RollBackSecret(ctx, secretName, secretPath, versionList[index-2].Version)
		if err != nil {
			return err
		}
	} else if index == 1 {
		err := uc.client.DeleteSecret(ctx, secretName, secretPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uc *VaultUsercase) DeleteSecret(ctx context.Context, req pb.SecRequest) error {
	secret, err := req.ConvertRequest()
	if err != nil {
		return pb.ErrorInputArgError("convert to secret failed: %s", err)
	}
	if !verifySecret(secret) {
		return errorSecretVerifyFailed
	}
	secretName := secret.SecretName
	secretPath := secret.SecretPath
	policyPath := secret.PolicyName

	err = uc.client.DeletePolicy(ctx, policyPath)
	if err != nil {
		return pb.ErrorInternalServiceError("delete policy of %s in %s failed", secretPath, secretName)
	}
	err = uc.client.DeleteSecret(ctx, secretName, secretPath)
	if err != nil {
		return pb.ErrorInternalServiceError("delete secret %s in %s failed", secretPath, secretName)
	}

	return nil
}

func verifySecret(sec *pb.SecretRequest) bool {
	for _, char := range sec.FullPath {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '-' && char != '/' {
			return false
		}
	}
	return true
}
