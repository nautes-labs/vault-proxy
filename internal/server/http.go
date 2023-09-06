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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"regexp"

	v1 "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	"github.com/nautes-labs/vault-proxy/internal/biz/auth"
	"github.com/nautes-labs/vault-proxy/internal/conf"
	"github.com/nautes-labs/vault-proxy/internal/service"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/selector"
	"github.com/go-kratos/kratos/v2/middleware/validate"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/go-kratos/swagger-api/openapiv2"
)

var (
	BasicAPIList []string = []string{
		`\/api\.vaultproxy\.v1\.Secret\/.*`,
		`\/api\.vaultproxy\.v1\.Auth\/.*`,
	}
	GrantAPIList []string = []string{
		`\/api\.vaultproxy\.v1\.AuthGrant\/.*`,
	}
)

func getCheckList(checkType int) selector.MatchFunc {
	var checkList []string
	switch checkType {
	case auth.BASIC:
		checkList = BasicAPIList
	case auth.GRANT:
		checkList = GrantAPIList
	}
	return func(ctx context.Context, operation string) bool {
		for _, v := range checkList {
			ok, err := regexp.MatchString(v, operation)
			if err != nil {
				return false
			}
			if ok {
				return true
			}
		}
		return false
	}
}

// Start a new http server, it has following step
//
// 1. Add several middleware(authentication , authorization, tracing)
// 2. Read http basic setting from configmap, and append http server options list
// 3. Make a http instance
// 4. Regist api to it
func NewHTTPServer(c *conf.Server,
	secretService *service.SecretService,
	authService *service.AuthService,
	authGrantService *service.AuthGrantService,
	healthService *service.HealthService,
	logger log.Logger) *http.Server {

	var opts = []http.ServerOption{
		http.Middleware(
			validate.Validator(),
			recovery.Recovery(),
			selector.Server(
				auth.Authenticate(),
				auth.Authorize(c, auth.BASIC),
			).Match(getCheckList(auth.BASIC)).Build(),
			selector.Server(
				auth.Authenticate(),
				auth.Authorize(c, auth.GRANT),
			).Match(getCheckList(auth.GRANT)).Build(),
		),
	}

	if c.Http.Network != "" {
		opts = append(opts, http.Network(c.Http.Network))
	}
	if c.Http.Addr != "" {
		opts = append(opts, http.Address(c.Http.Addr))
	}
	if c.Http.Timeout != nil {
		opts = append(opts, http.Timeout(c.Http.Timeout.AsDuration()))
	}
	if c.Http.Cert != nil {
		cert, err := tls.LoadX509KeyPair(c.Http.Cert.CertFile, c.Http.Cert.KeyFile)
		if err != nil {
			log.Fatal(err)
		}
		caCert, err := os.ReadFile(c.Http.Cert.CaCert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig := &tls.Config{
			ClientCAs:    caCertPool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			Certificates: []tls.Certificate{cert},
		}
		opts = append(opts, http.TLSConfig(tlsConfig))
	}

	srv := http.NewServer(opts...)
	openAPIhandler := openapiv2.NewHandler()
	srv.HandlePrefix("/q/", openAPIhandler)
	v1.RegisterSecretHTTPServer(srv, secretService)
	v1.RegisterAuthHTTPServer(srv, authService)
	v1.RegisterAuthGrantHTTPServer(srv, authGrantService)
	v1.RegisterHealthHTTPServer(srv, healthService)
	return srv
}
