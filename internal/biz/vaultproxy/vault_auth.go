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

	vault "github.com/hashicorp/vault/api"
)

var (
	innerUser []string = []string{"ARGO", "BASE", "CLUSTER", "REPO", "RUNTIME"}
)

func (uc *VaultUsercase) EnableAuth(ctx context.Context, req *pb.AuthRequest) error {
	if !verifyName(req.ClusterName) {
		return errorNameVerifyFailed
	}

	path := req.ClusterName
	configPath := fmt.Sprintf("auth/%s/config", path)
	cfg, err := uc.client.Read(ctx, configPath)
	if err != nil {
		return pb.ErrorInternalServiceError("get auth %s info failed: %s", path, err)
	}

	if cfg == nil {
		authOpts := &vault.MountInput{
			Type: req.AuthType,
		}
		uc.log.WithContext(ctx).Infof("create new auth %s", path)
		err := uc.client.EnableAuth(ctx, path, authOpts)
		if err != nil {
			return pb.ErrorInternalServiceError("create auth %s failed: %s", path, err)
		}
	}

	opts := map[string]interface{}{
		"kubernetes_host":    req.Kubernetes.Url,
		"kubernetes_ca_cert": req.Kubernetes.Cabundle,
		"token_reviewer_jwt": req.Kubernetes.Usertoken,
	}
	uc.log.WithContext(ctx).Infof("update auth %s", path)
	_, err = uc.client.Write(ctx, configPath, opts)
	if err != nil {
		return pb.ErrorInternalServiceError("update auth %s failed: %s", path, err)
	}
	return nil
}

func (uc *VaultUsercase) DisableAuth(ctx context.Context, req *pb.AuthRequest) error {
	if !verifyName(req.ClusterName) {
		return errorNameVerifyFailed
	}

	uc.log.WithContext(ctx).Infof("disable auth %s", req.ClusterName)
	err := uc.client.DisableAuth(ctx, req.ClusterName)
	if err != nil {
		return pb.ErrorInternalServiceError("delete auth %s failed: %s", req.ClusterName, err)
	}
	return nil
}

func (uc *VaultUsercase) GetAuth(ctx context.Context, authName string) (map[string]interface{}, error) {
	authPath := fmt.Sprintf("auth/%s/config", authName)
	auth, err := uc.client.Read(ctx, authPath)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, pb.ErrorResourceNotFound("can not find auth %s", authName)
	}
	return auth.Data, nil
}

func (uc *VaultUsercase) CreateRole(ctx context.Context, req *pb.AuthroleRequest) error {
	if !verifyName(req.ClusterName) || !verifyName(req.DestUser) {
		return errorNameVerifyFailed
	}

	_, err := uc.GetAuth(ctx, req.ClusterName)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("auth/%s/role/%s", req.ClusterName, req.DestUser)
	opts := map[string]interface{}{
		"bound_service_account_namespaces": req.GetK8S().Namespaces,
		"bound_service_account_names":      req.GetK8S().Serviceaccounts,
	}

	uc.log.WithContext(ctx).Infof("create or update role %s", path)
	_, err = uc.client.Write(ctx, path, opts)
	if err != nil {
		return pb.ErrorInternalServiceError("create role %s failed: %s", req.DestUser, err)
	}
	return nil
}

func (uc *VaultUsercase) DeleteRole(ctx context.Context, req *pb.AuthroleRequest) error {
	if !verifyName(req.ClusterName) || !verifyName(req.DestUser) {
		return errorNameVerifyFailed
	}

	_, err := uc.GetAuth(ctx, req.ClusterName)
	if err != nil {
		if pb.IsResourceNotFound(err) {
			return nil
		}
		return err
	}

	path := fmt.Sprintf("auth/%s/role/%s", req.ClusterName, req.DestUser)
	uc.log.WithContext(ctx).Infof("delete role %s", path)
	_, err = uc.client.Delete(ctx, path)
	if err != nil {
		return pb.ErrorInternalServiceError("delete role %s failed: %s", req.DestUser, err)
	}
	return nil
}

func (uc *VaultUsercase) GrantPermision(ctx context.Context, req pb.AuthGrantRequest) error {
	role, secret, err := req.ConvertToAuthPolicyReqeuest()
	if err != nil {
		return pb.ErrorInputArgError("convert grant policy request failed, %s", err)
	} else if !verifyName(role.RolePath) {
		return pb.ErrorInputArgError("input cluster name or user name is wrong format.")
	}

	if err := uc.secretIsExist(ctx, *secret); err != nil {
		return pb.ErrorResourceNotFound("secret %s is broken, you may need to recreate it: %s", secret.FullPath, err)
	}

	// Get info from role
	roleCFG, err := uc.client.Read(ctx, role.RolePath)
	if err != nil || roleCFG == nil {
		return pb.ErrorResourceNotFound("get %s role info failed: %s", role.Name, err)
	}

	// Append new policy and update role
	policyList := roleCFG.Data["token_policies"].([]interface{})
	for _, policy := range policyList {
		if policy == secret.PolicyName {
			uc.log.WithContext(ctx).Debugf("policy %s is already existed , skip", secret.PolicyName)
			return nil
		}
	}

	roleCFG.Data["token_policies"] = append(policyList, secret.PolicyName)
	_, err = uc.client.Write(ctx, role.RolePath, roleCFG.Data)
	if err != nil {
		return pb.ErrorInternalServiceError("grant %s to %s failed: %s", secret.FullPath, role.Name, err)
	}

	return nil
}

func (uc *VaultUsercase) RevokePermision(ctx context.Context, req pb.AuthGrantRequest) error {
	role, secret, err := req.ConvertToAuthPolicyReqeuest()
	if err != nil {
		return pb.ErrorInputArgError("convert grant policy request failed, %s", err)
	} else if !verifyName(role.RolePath) {
		return pb.ErrorInputArgError("input cluster name or user name is wrong format.")
	}

	// Get info from role
	roleCFG, err := uc.client.Read(ctx, role.RolePath)
	if err != nil {
		return pb.ErrorResourceNotFound("get %s role info failed: %s", role.Name, err)
	} else if roleCFG == nil {
		uc.log.WithContext(ctx).Warnf("user not exist, %s", role.RolePath)
		return nil
	}

	// Loop role policy list, remove specify policy and then update role
	var newPolicyList []interface{}
	policyList := roleCFG.Data["token_policies"].([]interface{})
	removePolicy := secret.PolicyName
	for _, v := range policyList {
		if v != removePolicy {
			newPolicyList = append(newPolicyList, v)
		}
	}

	roleCFG.Data["token_policies"] = newPolicyList
	_, err = uc.client.Write(ctx, role.RolePath, roleCFG.Data)
	if err != nil {
		return pb.ErrorInternalServiceError("revoke policy %s from %s failed: %s", secret.PolicyName, role.RolePath, err)
	}

	return nil
}

func (uc *VaultUsercase) secretIsExist(ctx context.Context, secReq pb.SecretRequest) error {
	policyData, err := uc.client.GetPolicy(ctx, secReq.PolicyName)
	if err != nil {
		return fmt.Errorf("get policy for secret %s failed. %s", secReq.FullPath, err)
	}
	if policyData == "" {
		return fmt.Errorf("policy for secret %s is empty.", secReq.FullPath)

	}

	_, err = uc.client.GetSecret(ctx, secReq.SecretType, secReq.SecretPath)
	if err != nil {
		return fmt.Errorf("get secret %s failed. %s", secReq.FullPath, err)
	}
	return nil
}
