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
	"text/template"

	"github.com/go-kratos/kratos/v2/log"

	pb "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	"github.com/nautes-labs/vault-proxy/internal/conf"
	vpData "github.com/nautes-labs/vault-proxy/internal/data"
)

var (
	templateList = map[string]string{
		"GitPathTemplate":              "{{.Providertype}}/{{.Repoid}}/{{.Username}}/{{.Permission}}",
		"GitPolicyPathTemplate":        "{{.Providertype}}-{{.Repoid}}-{{.Username}}-{{.Permission}}",
		"RepoPathTemplate":             "{{.Providerid}}/{{.Repotype}}/{{.Repoid}}/{{.Username}}/{{.Permission}}",
		"RepoPolicyPathTemplate":       "{{.Providerid}}-{{.Repotype}}-{{.Repoid}}-{{.Username}}-{{.Permission}}",
		"ClusterPathTemplate":          "{{.Clustertype}}/{{.Clusterid}}/{{.Username}}/{{.Permission}}",
		"ClusterPolicyPathTemplate":    "{{.Clustertype}}-{{.Clusterid}}-{{.Username}}-{{.Permission}}",
		"TenantGitPathTemplate":        "git/{{.Id}}/{{.Permission}}",
		"TenantGitPolicyPathTemplate":  "tenant-git-{{.Id}}-{{.Permission}}",
		"TenantRepoPathTemplate":       "repo/{{.Id}}/{{.Permission}}",
		"TenantRepoPolicyPathTemplate": "tenant-repo-{{.Id}}-{{.Permission}}",
	}
)

var (
	errorNameVerifyFailed   = pb.ErrorInputArgError("input cluster name or dest user name format is wrong.")
	errorSecretVerifyFailed = pb.ErrorInputArgError("secret verify failed")
)

type VaultUsercase struct {
	client     vpData.VaultClientInterface
	tmpl       template.Template
	casbinFile string
	log        *log.Helper
}

func NewVaultUsercase(client vpData.VaultClientInterface, cfg *conf.Server, logger log.Logger) *VaultUsercase {
	return &VaultUsercase{
		client:     client,
		tmpl:       NewTemplateList(),
		casbinFile: cfg.Authorization.Resource.Acl,
		log:        log.NewHelper(logger)}
}

func NewTemplateList() template.Template {
	var tmpl template.Template
	for k, v := range templateList {
		template.Must(tmpl.New(k).Parse(v))
	}
	return tmpl
}

func (uc *VaultUsercase) Health() bool {
	return uc.client.Health()
}

func verifyName(input string) bool {
	for _, char := range input {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '-' && char != '/' {
			return false
		}
	}
	return true
}
