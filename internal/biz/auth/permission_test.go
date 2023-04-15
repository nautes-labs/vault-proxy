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
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-kratos/kratos/v2/transport"
	v1 "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	"github.com/nautes-labs/vault-proxy/internal/biz/auth"
	"github.com/nautes-labs/vault-proxy/internal/conf"
)

var auther *auth.Authorizer
var resList map[string]string

var _ = BeforeSuite(func() {
	var err error
	auther, err = auth.NewAuthorizer(&conf.Server_Authorization{
		Resource: &conf.Server_Authorization_Casbin{
			Acl: "../../../configs/casbin/resource_acl.csv",
		},
		Permission: &conf.Server_Authorization_Casbin{
			Acl: "../../../configs/casbin/permission_acl.csv",
		},
	},
		&conf.Nautes{
			TenantName: []string{
				"tenant",
			},
		})

	resList = map[string]string{
		"git":         "git/gitlab",
		"repo":        "repo/nexus",
		"cluster":     "cluster/k8s",
		"auth":        "auth/kubernetes",
		"tenant/repo": "tenant/repo/harbor",
	}
	Expect(err).Should(BeNil())

})

var _ = Describe("Permission", func() {
	Context("API", func() {
		user := "API"

		It("create/delete git resource is allowed", func() {
			resours := []string{resList["git"], resList["cluster"], resList["tenant/repo"]}
			for _, res := range resours {
				err := auther.CheckSecretPermission(context.Background(), user, res, "POST")
				Expect(err).Should(BeNil())

				err = auther.CheckSecretPermission(context.Background(), user, res, "DELETE")
				Expect(err).Should(BeNil())
			}
		})

		It("create/delete other resource is not allowed", func() {
			resours := []string{resList["repo"], resList["auth"]}
			for _, res := range resours {
				err := auther.CheckSecretPermission(context.Background(), user, res, "POST")
				Expect(err).ShouldNot(BeNil())

				err = auther.CheckSecretPermission(context.Background(), user, res, "DELETE")
				Expect(err).ShouldNot(BeNil())
			}

		})

		It("grant/revoke git to argo operator is allowed", func() {
			err := auther.CheckGrantPermission(context.Background(), user, resList["git"], &v1.GrantTarget{
				RolePath: "auth/tenant/ARGO",
				Name:     "ARGO",
			})
			Expect(err).Should(BeNil())
		})

		It("grant/revoke git to other user is not allowed", func() {
			err := auther.CheckGrantPermission(context.Background(), user, resList["git"], &v1.GrantTarget{
				RolePath: "auth/tenant/RUNTIME",
				Name:     "RUNTIME",
			})
			Expect(err).ShouldNot(BeNil())
		})

		It("grant/revoke other sec to argo operator is not allowed", func() {
			err := auther.CheckGrantPermission(context.Background(), user, resList["cluster"], &v1.GrantTarget{
				RolePath: "auth/tenant/ARGO",
				Name:     "ARGO",
			})
			Expect(err).ShouldNot(BeNil())
		})
	})

	Context("RUNTIME", func() {
		user := "RUNTIME"
		It("can not create and delete any resource", func() {
			for _, res := range resList {
				err := auther.CheckSecretPermission(context.Background(), user, res, "POST")
				Expect(err).ShouldNot(BeNil())

				err = auther.CheckSecretPermission(context.Background(), user, res, "DELETE")
				Expect(err).ShouldNot(BeNil())
			}
		})

		It("create role will seccuss", func() {
			res := "auth/kubernetes/role/humen"
			err := auther.CheckSecretPermission(context.Background(), user, res, "POST")
			Expect(err).Should(BeNil())
			err = auther.CheckSecretPermission(context.Background(), user, res, "DELETE")
			Expect(err).Should(BeNil())
		})

		It("create role in tenant will failed", func() {
			res := "auth/tenant/role/ARGO"
			err := auther.CheckSecretPermission(context.Background(), user, res, "POST")
			Expect(err).ShouldNot(BeNil())
			err = auther.CheckSecretPermission(context.Background(), user, res, "DELETE")
			Expect(err).ShouldNot(BeNil())
		})

		It("grant repo to argo will failed", func() {
			err := auther.CheckGrantPermission(context.Background(), user, resList["repo"], &v1.GrantTarget{
				RolePath: "auth/testAuth/ARGO",
				Name:     "ARGO",
			})
			Expect(err).ShouldNot(BeNil())
		})
	})
})

var _ = Describe("Other", func() {
	It("read and write user name from context", func() {
		ctx := context.Background()
		testInfo := "this is the message for rw context"
		ctx = auth.NewAuthContext(ctx, testInfo)
		info := auth.FromAuthContext(ctx)
		Expect(info).Should(Equal(testInfo))
	})

	It("basic type auth proeccess pass", func() {
		ctx := context.Background()
		ctx = transport.NewServerContext(ctx, mockTransporter{Method: "POST"})
		ctx = auth.NewAuthContext(ctx, "CLUSTER")
		err := auth.AuthProcess(ctx, auther, auth.BASIC, &mockSecret{
			FullPath: "cluster/kubernetes/tenant/default/admin",
		})
		Expect(err).Should(BeNil())
	})

	It("basic type auth proeccess pass", func() {
		ctx := context.Background()
		ctx = transport.NewServerContext(ctx, mockTransporter{Method: "POST"})
		ctx = auth.NewAuthContext(ctx, "CLUSTER")
		err := auth.AuthProcess(ctx, auther, auth.GRANT, &mockSecret{
			FullPath:       "cluster/kubernetes/pipeline/default/admin",
			TargetRolePath: "/auth/pipeline/RUNTIME",
			TargetName:     "RUNTIME",
		})
		Expect(err).Should(BeNil())
	})
})

var _ = Describe("Authentication", func() {
	It("get user from tls", func() {
		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{
							Subject: pkix.Name{
								CommonName: "ARGO",
							},
						},
					},
				},
			},
		}
		name, err := auth.GetUsername(req)
		Expect(err).Should(BeNil())
		Expect(name).Should(Equal("ARGO"))
	})

	It("when request without client key pair, get error", func() {
		req := &http.Request{}
		_, err := auth.GetUsername(req)
		Expect(err).ShouldNot(BeNil())

	})
})
