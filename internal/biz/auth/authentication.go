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

package auth

import (
	"context"
	"net/http"

	api "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
)

type AuthUser struct{}

func GetUsername(req *http.Request) (string, error) {
	if req.TLS != nil && len(req.TLS.VerifiedChains) > 0 && len(req.TLS.VerifiedChains[0]) > 0 {
		var commonName = req.TLS.VerifiedChains[0][0].Subject.CommonName
		return commonName, nil
	} else {
		return "", api.ErrorAuthFailed("can not find user info in client keypair")
	}
}

func NewAuthContext(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, AuthUser{}, user)
}
func FromAuthContext(ctx context.Context) string {
	return ctx.Value(AuthUser{}).(string)
}
