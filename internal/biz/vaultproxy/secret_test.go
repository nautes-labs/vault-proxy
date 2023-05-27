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

package vaultproxy_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/go-kratos/kratos/v2/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vault "github.com/hashicorp/vault/api"
	vpApi "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	"github.com/nautes-labs/vault-proxy/internal/biz/vaultproxy"
	"github.com/nautes-labs/vault-proxy/internal/conf"
	vpData "github.com/nautes-labs/vault-proxy/internal/data"
)

type mockSecret struct {
	SecretName string
	SecretPath string
	SecretType string
	FullPath   string
	PolicyName string
	SecretData map[string]interface{}
	PolicyData string
	err        error
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

type mockPolicyRequest struct {
	ClusterName string
	DestUser    string
	Secret      mockSecret
}

func (mpr *mockPolicyRequest) ConvertToAuthPolicyReqeuest() (*vpApi.GrantTarget, *vpApi.SecretRequest, error) {
	secretMeta, _ := mpr.Secret.GetNames()
	return vpApi.ConvertAuthGrantRequest(mpr.ClusterName, mpr.DestUser, secretMeta)
}

var vpClient *vaultproxy.VaultUsercase
var vaultRawClient *vault.Client
var casbinPermissionFile string
var _ = BeforeSuite(func() {
	vaultClientCfg := conf.Data{
		Vault: &conf.Data_Vault{
			Addr:  "http://127.0.0.1:8200",
			Token: "test",
		},
	}

	vaultClient := vpData.NewVaultClient(&vaultClientCfg, log.DefaultLogger)
	casbinPermissionFile = "/tmp/permission.acl"
	vpClient = vaultproxy.NewVaultUsercase(vaultClient, &conf.Server{
		Authorization: &conf.Server_Authorization{
			Resource: &conf.Server_Authorization_Casbin{Acl: casbinPermissionFile},
		},
	}, log.DefaultLogger)

	cfg := vault.DefaultConfig()
	cfg.Address = "http://127.0.0.1:8200"

	var err error
	vaultRawClient, err = vault.NewClient(cfg)
	Expect(err).Should(BeNil())
	vaultRawClient.SetToken("test")
})

var _ = Describe("Secret", func() {
	var vaultServer *exec.Cmd
	var secret *mockSecret

	BeforeEach(func() {
		vaultServer = exec.Command("vault", "server", "-dev", "-dev-root-token-id=test")
		err := vaultServer.Start()
		Expect(err).Should(BeNil())

		for {
			vaultServerHealthCheck := exec.Command("vault", "status", "-address=http://127.0.0.1:8200")
			err := vaultServerHealthCheck.Run()
			if err == nil {
				break
			}
		}

		mountPath := "git"
		mountInput := &vault.MountInput{
			Type:                  "kv",
			Description:           "",
			Config:                vault.MountConfigInput{},
			Local:                 false,
			SealWrap:              false,
			ExternalEntropyAccess: false,
			Options: map[string]string{
				"version": "2",
			},
			PluginName: "",
		}
		vaultRawClient.Sys().Mount(mountPath, mountInput)

		secret = &mockSecret{
			SecretName: "git",
			SecretPath: "gitlab/123",
			SecretType: vpApi.GIT.String(),
			FullPath:   "git/gitlab/123",
			PolicyName: "git-gitlab-123",
			SecretData: map[string]interface{}{"account": "123"},
			PolicyData: "path \"git/data/gitlab/123\" {\n    capabilities = [\"read\"]\n}",
		}
	})

	AfterEach(func() {
		err := vaultServer.Process.Kill()
		Expect(err).Should(BeNil())
	})

	Describe("Create Secret", func() {
		Context("if a new secret", func() {
			It("will create success", func() {
				vpClient.CreateSecret(context.Background(), secret)
				rst, _ := vaultRawClient.KVv2(secret.SecretName).Get(context.Background(), secret.SecretPath)
				Expect(rst.Data).To(Equal(secret.SecretData))
			})

			Context("when create policy failed", func() {
				It("will failed and remove secret", func() {
					secret.PolicyName = ""

					_, err := vpClient.CreateSecret(context.Background(), secret)
					Expect(vpApi.IsInputArgError(err)).Should(BeTrue())

					_, err = vaultRawClient.KVv2(secret.SecretName).Get(context.Background(), secret.SecretPath)
					Expect(err).NotTo(BeNil())
				})
			})

			It("when req is not legal, create secret failed", func() {
				req := &mockSecret{
					err: errors.New("err"),
				}
				_, err := vpClient.CreateSecret(context.Background(), req)
				Expect(vpApi.IsInputArgError(err)).Should(BeTrue())

				req = &mockSecret{
					FullPath: "%(*&%",
				}

				_, err = vpClient.CreateSecret(context.Background(), req)
				Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
			})

		})

		Context("secret has already exist", func() {
			BeforeEach(func() {
				_, err := vpClient.CreateSecret(context.Background(), secret)
				Expect(err).Should(BeNil())
			})

			Context("when create policy failed", func() {
				It("will update secret failed and rollback to the pre version", func() {
					secret.PolicyName = ""

					_, err := vpClient.CreateSecret(context.Background(), secret)
					Expect(vpApi.IsInputArgError(err)).Should(BeTrue())

					rst, _ := vaultRawClient.KVv2(secret.SecretName).Get(context.Background(), secret.SecretPath)
					Expect(len(rst.Data)).Should(BeNumerically("==", 1))
				})
			})
		})
	})

	Describe("Delete Secret", func() {
		BeforeEach(func() {
			_, err := vpClient.CreateSecret(context.Background(), secret)
			Expect(err).Should(BeNil())
		})

		It("delete secret seccessed", func() {
			err := vpClient.DeleteSecret(context.Background(), secret)
			Expect(err).Should(BeNil())
		})

		Context("delete policy failed", func() {
			It("will return internal error", func() {
				// secret.PolicyName = "newPolicyName"
				// wantErr := vpApi.ErrorInternalServiceError("delete policy of %s in %s failed", secret.SecretPath, secret.SecretName)

				// err := vpClient.DeleteSecret(context.Background(), secret)
				// Expect(err).To(Equal(wantErr))
			})

			It("when req is not legal, create secret failed", func() {
				req := &mockSecret{
					err: errors.New("err"),
				}
				err := vpClient.DeleteSecret(context.Background(), req)
				Expect(vpApi.IsInputArgError(err)).Should(BeTrue())

				req = &mockSecret{
					FullPath: "%(*&%",
				}

				err = vpClient.DeleteSecret(context.Background(), req)
				Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
			})
		})
	})

	Describe("Health", func() {
		It("return true when vault is running", func() {
			Expect(vpClient.Health()).Should(BeTrue())
		})
	})

})

var _ = Describe("Auth", func() {
	var vaultServer *exec.Cmd
	var baseAuth *vpApi.AuthRequest
	var baseRole *vpApi.AuthroleRequest
	var baseGrant *mockPolicyRequest

	BeforeEach(func() {
		vaultServer = exec.Command("vault", "server", "-dev", "-dev-root-token-id=test")
		err := vaultServer.Start()
		Expect(err).Should(BeNil())

		for {
			vaultServerHealthCheck := exec.Command("vault", "status", "-address=http://127.0.0.1:8200")
			err := vaultServerHealthCheck.Run()
			if err == nil {
				break
			}
		}

		baseAuth = &vpApi.AuthRequest{
			ClusterName: "myCluster",
			AuthType:    "kubernetes",
			Kubernetes: &vpApi.Kubernetes{
				Url: "https://127.0.0.1:6443",
				Cabundle: `-----BEGIN CERTIFICATE-----
					MIIBeDCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3Mtc2Vy
					dmVyLWNhQDE2NjU3MTQ2MDIwHhcNMjIxMDE0MDIzMDAyWhcNMzIxMDExMDIzMDAy
					WjAjMSEwHwYDVQQDDBhrM3Mtc2VydmVyLWNhQDE2NjU3MTQ2MDIwWTATBgcqhkjO
					PQIBBggqhkjOPQMBBwNCAAT7OlsZugCRj1vwdIZeUV7msSIFAklTesfA/TLpbg07
					h+pqACyDKUSrG/ppk6NZheEjKG76rC1Ce7KFgsbzlF4Po0IwQDAOBgNVHQ8BAf8E
					BAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU8demdxg87w35AeW37L1/
					dmNeZZIwCgYIKoZIzj0EAwIDSQAwRgIhAKSXFcgPQTn4gQRQhBLxCJiPwJyC3Vc0
					wpBiyGE7exo8AiEAq9SP2sMm64ZAiI7QNSGQURKNPmhVcS7OuVnEMta63dM=
					-----END CERTIFICATE-----`,
				Token: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImlpSFBBMXZ6eHRUaFNFcy01alU3YkhSaFJYbzVsS0Z5RXpNR2V6ZnJlb0UifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJwcm9qZWN0LTI0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tcWQ2bDUiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjIxMTNiY2VkLTVlYzItNDdhZS1iMWJhLTE5MmM5ZGJhMmJiOCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpwcm9qZWN0LTI0OmRlZmF1bHQifQ.iTeppMY9p-P9xT0OgCvShM0Ln38bohnGDnpE4lu6iFpNUUIHV-kdzozHWI_5DHlFo8v55MXXqVFqmjwjIzgtKqZYasyfE36XHL_DTzdsfWqtHbB33nwLLV3iGYnoEOxYsoal4JQV8LMpSnZocRdOjI2WM1Bm8_2H1dh3FZQ-4BstHha4Xx9zveNsviFvEprJ5j1z4nQwSiGJy6-aFx5EF3AKN0eokY8pZX5xIOBwULiE41Bjj1BpbyAM-b38fzVe_SSTeaU1ycaUXofd155lyxE7QLOE-6XLLP0F4wS9LPf7Z6ufcdxypxB3R3cvuvryBdCIiGa738g6KIjMKDDzIw",
			},
		}

		baseRole = &vpApi.AuthroleRequest{
			ClusterName: baseAuth.ClusterName,
			DestUser:    "RUNTIME",
			Role: &vpApi.AuthroleRequest_K8S{
				K8S: &vpApi.KubernetesAuthRoleMeta{
					Namespaces:      "default",
					ServiceAccounts: "default",
				},
			},
		}

		baseGrant = &mockPolicyRequest{
			ClusterName: baseAuth.ClusterName,
			DestUser:    baseRole.DestUser,
			Secret: mockSecret{
				SecretName: "git",
				SecretPath: "gitlab/123",
				SecretType: vpApi.GIT.String(),
				FullPath:   "git/gitlab/123",
				PolicyName: "git-gitlab-123",
				SecretData: map[string]interface{}{"account": "123"},
				PolicyData: "path \"git/data/gitlab/123\" {\n    capabilities = [\"read\"]\n}",
			},
		}
	})

	AfterEach(func() {
		err := vaultServer.Process.Kill()
		Expect(err).Should(BeNil())
	})

	Describe("Create Auth", func() {
		Context("it is a new auth", func() {
			It("create a new auth", func() {
				err := vpClient.EnableAuth(context.Background(), baseAuth)
				Expect(err).Should(BeNil())
			})

			Context("cluster name has invaild symbol", func() {
				It("create auth failed", func() {
					baseAuth.ClusterName = "vv$^*(hh"

					err := vpClient.EnableAuth(context.Background(), baseAuth)
					Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
				})
			})
		})
		Context("it already exist", func() {
			BeforeEach(func() {
				err := vpClient.EnableAuth(context.Background(), baseAuth)
				Expect(err).Should(BeNil())
			})
			It("update auth url", func() {
				newUrl := "https://192.168.3.1:6443"
				baseAuth.Kubernetes.Url = newUrl
				rolePath := fmt.Sprintf("auth/%s/config", baseAuth.ClusterName)

				err := vpClient.EnableAuth(context.Background(), baseAuth)
				Expect(err).Should(BeNil())

				cfg, err := vaultRawClient.Logical().Read(rolePath)
				Expect(err).Should(BeNil())
				Expect(cfg.Data["kubernetes_host"]).Should(Equal(newUrl))
			})

			It("update auth cabundle", func() {
				newCa := "newca"
				baseAuth.Kubernetes.Cabundle = newCa
				rolePath := fmt.Sprintf("auth/%s/config", baseAuth.ClusterName)

				err := vpClient.EnableAuth(context.Background(), baseAuth)
				Expect(err).Should(BeNil())

				cfg, err := vaultRawClient.Logical().Read(rolePath)
				Expect(err).Should(BeNil())
				Expect(cfg.Data["kubernetes_ca_cert"]).Should(Equal(newCa))
			})

			It("update auth token", func() {
				newToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImlpSFBBMXZ6eHRUaFNFcy01alU3YkhSaFJYbzVsS0Z5RXpNR2V6ZnJlb0UifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJwcm9qZWN0LTQwIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbHBtZmciLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImVhMzUwZThhLTljZTItNGYxZC05ODQwLTE5MmNmYWFhY2MwMCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpwcm9qZWN0LTQwOmRlZmF1bHQifQ.I_krS28u76wRzvxDSkJReeIekV8Ox9kLvyFu9h1sB_DmWlXWswE8tvOBB_KRtrOnHoQFPNOtlbp96yEHzQVgMLNnfd2pcg6OATZCx2v02A7Qe7T3noQVbR3w926vibouXBvO_IvxHgJrRrEV4-J7ndb19JeBYj3j0_qSELgtla_-_ld-Zm8zQlHb-EvKC6GAu_O1AFVo74OBLiPJyMDfmsImAxvXa7Q43pg2rW5OEDDCs8VrKTAi6aqUkRG-tdWA1-It6lIjEsJ5w9iDlD_-rbi-72Qm-2o9rzQzWD3Y_eJTpDt35oXHHdTFp_XzoMdXVqSTfOHkPqGy2lM6knsoIA"
				baseAuth.Kubernetes.Token = newToken
				rolePath := fmt.Sprintf("auth/%s/config", baseAuth.ClusterName)

				err := vpClient.EnableAuth(context.Background(), baseAuth)
				Expect(err).Should(BeNil())

				_, err = vaultRawClient.Logical().Read(rolePath)
				Expect(err).Should(BeNil())
			})
		})

	})
	Describe("Delete Auth", func() {
		BeforeEach(func() {
			err := vpClient.EnableAuth(context.Background(), baseAuth)
			Expect(err).Should(BeNil())
		})

		It("delete a exited auth", func() {
			err := vpClient.DisableAuth(context.Background(), baseAuth)
			Expect(err).Should(BeNil())
		})

		It("will failed, when cluster name has invaild symbol", func() {
			baseAuth.ClusterName = "vv$^*(hh"

			err := vpClient.EnableAuth(context.Background(), baseAuth)
			Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
		})

	})

	Describe("Create Role", func() {
		BeforeEach(func() {
			err := vpClient.EnableAuth(context.Background(), baseAuth)
			Expect(err).Should(BeNil())
		})
		It("create a new role", func() {
			err := vpClient.CreateRole(context.Background(), baseRole)
			Expect(err).Should(BeNil())
		})
		It("create failed when cluster name has invaild symbol", func() {
			baseRole.ClusterName = "njasd%(^ihiad"

			err := vpClient.CreateRole(context.Background(), baseRole)
			Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
		})
		It("update a an existed role", func() {
			newNs := "kube-system"
			baseRole.Role = &vpApi.AuthroleRequest_K8S{
				K8S: &vpApi.KubernetesAuthRoleMeta{
					Namespaces:      newNs,
					ServiceAccounts: "default",
				},
			}
			rolePath := fmt.Sprintf("auth/%s/role/%s", baseRole.ClusterName, baseRole.DestUser)

			err := vpClient.CreateRole(context.Background(), baseRole)
			Expect(err).Should(BeNil())

			role, err := vaultRawClient.Logical().Read(rolePath)
			Expect(err).Should(BeNil())
			Expect(role.Data["bound_service_account_namespaces"].([]interface{})[0]).Should(Equal(newNs))

		})
	})

	Describe("Delete Role", func() {
		BeforeEach(func() {
			err := vpClient.EnableAuth(context.Background(), baseAuth)
			Expect(err).Should(BeNil())

			err = vpClient.CreateRole(context.Background(), baseRole)
			Expect(err).Should(BeNil())
		})
		It("delete a existed role", func() {
			err := vpClient.DeleteRole(context.Background(), baseRole)
			Expect(err).Should(BeNil())
		})
		It("delete failed when cluster name has invaild symbol", func() {
			baseRole.DestUser = "auywen%&^^asc"

			err := vpClient.DeleteRole(context.Background(), baseRole)
			Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
		})

		It("delete success when auth name do not existed", func() {
			testCluster := vpApi.AuthroleRequest{
				ClusterName: "notExistAuth",
				DestUser:    baseRole.DestUser,
				Role:        baseRole.Role,
			}

			err := vpClient.DeleteRole(context.Background(), &testCluster)
			Expect(err).Should(BeNil())
		})
	})

	Describe("Grant Permission", func() {
		var rolePath string
		BeforeEach(func() {
			err := vpClient.EnableAuth(context.Background(), baseAuth)
			Expect(err).Should(BeNil())

			err = vpClient.CreateRole(context.Background(), baseRole)
			Expect(err).Should(BeNil())

			mountInput := &vault.MountInput{
				Type:                  "kv",
				Description:           "",
				Config:                vault.MountConfigInput{},
				Local:                 false,
				SealWrap:              false,
				ExternalEntropyAccess: false,
				Options: map[string]string{
					"version": "2",
				},
				PluginName: "",
			}

			err = vaultRawClient.Sys().Mount("git", mountInput)
			Expect(err).Should(BeNil())

			_, err = vpClient.CreateSecret(context.Background(), &baseGrant.Secret)
			Expect(err).Should(BeNil())

			rolePath = fmt.Sprintf("auth/%s/role/%s", baseRole.ClusterName, baseRole.DestUser)
		})

		AfterEach(func() {
			os.Remove(casbinPermissionFile)
		})

		It("grant permission to a user", func() {

			err := vpClient.GrantPermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			role, err := vaultRawClient.Logical().Read(rolePath)
			Expect(err).Should(BeNil())
			Expect(role.Data["token_policies"].([]interface{})[0]).Should(Equal(baseGrant.Secret.PolicyName))
		})

		It("grant an exist policy will not duplicate append", func() {
			err := vpClient.GrantPermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			err = vpClient.GrantPermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			role, err := vaultRawClient.Logical().Read(rolePath)
			Expect(err).Should(BeNil())
			Expect(role.Data["token_policies"].([]interface{})[0]).Should(Equal(baseGrant.Secret.PolicyName))
		})

	})

	Describe("Revoke Permission", func() {
		var rolePath string
		BeforeEach(func() {
			err := vpClient.EnableAuth(context.Background(), baseAuth)
			Expect(err).Should(BeNil())

			err = vpClient.CreateRole(context.Background(), baseRole)
			Expect(err).Should(BeNil())

			mountInput := &vault.MountInput{
				Type:                  "kv",
				Description:           "",
				Config:                vault.MountConfigInput{},
				Local:                 false,
				SealWrap:              false,
				ExternalEntropyAccess: false,
				Options: map[string]string{
					"version": "2",
				},
				PluginName: "",
			}

			err = vaultRawClient.Sys().Mount("git", mountInput)
			Expect(err).Should(BeNil())

			_, err = vpClient.CreateSecret(context.Background(), &baseGrant.Secret)
			Expect(err).Should(BeNil())

			rolePath = fmt.Sprintf("auth/%s/role/%s", baseRole.ClusterName, baseRole.DestUser)
		})

		AfterEach(func() {
			os.Remove(casbinPermissionFile)
		})

		It("revoke permission from a user do not have any policy", func() {
			err := vpClient.RevokePermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			role, err := vaultRawClient.Logical().Read(rolePath)
			Expect(err).Should(BeNil())
			Expect(len(role.Data["token_policies"].([]interface{}))).Should(Equal(0))
		})

		It("revoke permission from a user", func() {
			err := vpClient.GrantPermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			err = vpClient.RevokePermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			role, err := vaultRawClient.Logical().Read(rolePath)
			Expect(err).Should(BeNil())
			Expect(len(role.Data["token_policies"].([]interface{}))).Should(Equal(0))
		})

		It("if role path has invaild symbol, grant, will faild", func() {
			baseGrant.ClusterName = "hhaous^&*"
			err := vpClient.GrantPermision(context.Background(), baseGrant)
			Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
			err = vpClient.RevokePermision(context.Background(), baseGrant)
			Expect(vpApi.IsInputArgError(err)).Should(BeTrue())
		})

		It("if role not exist, revoke will success", func() {
			err := vpClient.GrantPermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())

			rolePath = fmt.Sprintf("auth/%s/role/%s", baseRole.ClusterName, baseRole.DestUser)
			_, err = vaultRawClient.Logical().Delete(rolePath)
			Expect(err).Should(BeNil())

			err = vpClient.RevokePermision(context.Background(), baseGrant)
			Expect(err).Should(BeNil())
		})
	})
})
