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

package auth_test

import (
	"net/http"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	vpApi "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth Suite")
}

type mockSecret struct {
	SecretName     string
	SecretPath     string
	SecretType     string
	FullPath       string
	PolicyName     string
	SecretData     map[string]interface{}
	PolicyData     string
	TargetRolePath string
	TargetName     string
	err            error
}

func (m *mockSecret) ConvertRequest() (*vpApi.SecretRequest, error) {
	if m.err != nil {
		return nil, m.err
	}
	secretMeta, _ := m.GetNames()
	return &vpApi.SecretRequest{
		SecretMeta: *secretMeta,
		SecretData: m.SecretData,
		PolicyData: m.PolicyData,
	}, nil
}

func (m *mockSecret) GetNames() (*vpApi.SecretMeta, error) {
	return &vpApi.SecretMeta{
		SecretName: m.SecretName,
		SecretPath: m.SecretPath,
		SecretType: m.SecretType,
		FullPath:   m.FullPath,
		PolicyName: m.PolicyName,
	}, nil
}

func (m *mockSecret) ConvertToAuthPolicyReqeuest() (*vpApi.GrantTarget, *vpApi.SecretRequest, error) {
	secReq, err := m.ConvertRequest()
	return &vpApi.GrantTarget{
		RolePath: m.TargetRolePath,
		Name:     m.TargetName,
	}, secReq, err
}

type mockTransporter struct {
	Method string
}

func (t mockTransporter) Kind() transport.Kind {
	return transport.Kind("")
}

func (t mockTransporter) Endpoint() string {
	return ""
}

func (t mockTransporter) Operation() string {
	return ""
}

func (t mockTransporter) RequestHeader() transport.Header {
	return nil
}

func (t mockTransporter) ReplyHeader() transport.Header {
	return nil
}

func (t mockTransporter) Request() *http.Request {
	return &http.Request{
		Method: t.Method,
	}
}
