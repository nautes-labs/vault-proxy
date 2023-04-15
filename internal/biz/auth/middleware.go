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

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	hctx "github.com/go-kratos/kratos/v2/transport/http"
	api "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	"github.com/nautes-labs/vault-proxy/internal/conf"
)

func Authorize(c *conf.Server, checkType int) middleware.Middleware {
	authorizer, err := NewAuthorizer(c.Authorization, c.Nautes)
	if err != nil {
		panic("authorizer init failed")
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			err = AuthProcess(ctx, authorizer, checkType, req)
			if err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}
	}
}

func Authenticate() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				var user string
				ht, ok := tr.(*hctx.Transport)
				if !ok {
					return nil, api.ErrorInputArgError("Can not conver request type")
				}
				user, err = GetUsername(ht.Request())
				if err != nil {
					return nil, api.ErrorAuthFailed("Can not find user in client keypair")
				}

				ctx = NewAuthContext(ctx, user)
				defer func() {
					// Do something on exiting
				}()
			}
			return handler(ctx, req)
		}
	}
}
