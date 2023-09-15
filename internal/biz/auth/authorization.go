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
	"errors"
	"fmt"
	"net/http"

	v1 "github.com/nautes-labs/vault-proxy/api/vaultproxy/v1"
	"github.com/nautes-labs/vault-proxy/internal/conf"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/fsnotify/fsnotify"
	"github.com/go-kratos/kratos/v2/transport"

	"github.com/casbin/casbin/v2/model"

	scas "github.com/qiangmzsx/string-adapter/v2"
)

const (
	BASIC int = iota
	GRANT
)

var (
	resourceModel, _ = model.NewModelFromString(`
[request_definition]
r = usr, sec, act

[policy_definition]
p = usr, sec, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.usr == p.usr && regexMatch(r.sec, p.sec) && regexMatch(r.act, p.act)
`)
	permissionModel, _ = model.NewModelFromString(`
[request_definition]
r = usr, sec, dst

[policy_definition]
p = usr, sec, dst, eft

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = r.usr == p.usr && keyMatch(r.sec, p.sec) && keyMatch(r.dst, p.dst)
`)
	// Black list is use to block user to create special secret or auth
	blacklistModel, _ = model.NewModelFromString(`
[request_definition]
r = usr, res

[policy_definition]
p = usr, res

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.usr == p.usr && regexMatch(r.res, p.res)
`)
)

type Authorizer struct {
	ACLWatcher         *fsnotify.Watcher
	resourceInspector  *casbin.Enforcer
	grantInspector     *casbin.Enforcer
	blackListInspector *casbin.Enforcer
}

func NewAuthorizer(c *conf.Server_Authorization, nautesCFG *conf.Nautes) (*Authorizer, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	resourceInspector, err := casbin.NewEnforcer(resourceModel, fileadapter.NewAdapter(c.Resource.Acl))
	if err != nil {
		return nil, err
	}

	grantInspector, err := casbin.NewEnforcer(permissionModel, fileadapter.NewAdapter(c.Permission.Acl))
	if err != nil {
		return nil, err
	}

	acl := createBlackListACL(nautesCFG.TenantName)
	blacklistACL := scas.NewAdapter(acl)
	blackListInspector, err := casbin.NewEnforcer(blacklistModel, blacklistACL)
	if err != nil {
		return nil, err
	}

	author := &Authorizer{
		ACLWatcher:         watcher,
		resourceInspector:  resourceInspector,
		grantInspector:     grantInspector,
		blackListInspector: blackListInspector,
	}

	return author, nil
}

type Transport interface {
	Request() *http.Request
}

func GetSecretData(ctx context.Context, req interface{}) (user, resource, action string, err error) {
	user = FromAuthContext(ctx)

	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return "", "", "", errors.New("get request from ctx failed")
	}
	httpTransport, ok := tr.(Transport)
	if !ok {
		return "", "", "", errors.New("get request from ctx failed")
	}
	metadata, err := req.(v1.SecRequest).ConvertRequest()
	if err != nil {
		return "", "", "", err
	}
	resource = metadata.FullPath
	action = httpTransport.Request().Method
	return user, resource, action, nil
}

func getGrantData(ctx context.Context, req interface{}) (user, resource string, destUser *v1.GrantTarget, err error) {
	user = FromAuthContext(ctx)
	destUser, secret, err := req.(v1.AuthGrantRequest).ConvertToAuthPolicyReqeuest()
	if err != nil {
		return "", "", nil, err
	}
	resource = secret.FullPath
	return user, resource, destUser, nil
}

func (a *Authorizer) CheckSecretPermission(_ context.Context, user, resource, action string) error {
	ok, err := a.blackListInspector.Enforce(user, resource)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("authorize failed, %s %s is in blacklick", user, resource)
	}
	ok, err = a.resourceInspector.Enforce(user, resource, action)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("authorize failed, %s %s %s not allowed", user, action, resource)
	}
	return nil
}

// Grant check flow
// 1. Request are not in black list (blacklist is a regex list, current use to block runtime grant the role in tenant cluster)
// 2. User has grant permission in resource acl
// 3. User can grant resource to user
func (a *Authorizer) CheckGrantPermission(_ context.Context, user, resource string, dstUser *v1.GrantTarget) error {
	ok, err := a.blackListInspector.Enforce(user, dstUser.RolePath)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("authorize failed, %s %s is in blacklick", user, dstUser.RolePath)
	}

	ok, err = a.grantInspector.Enforce(user, resource, dstUser.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("authorize failed, %s can not grant %s to %s", user, resource, dstUser.RolePath)
	}
	return nil
}

func AuthProcess(ctx context.Context, auth *Authorizer, checkType int, req interface{}) error {
	// Steps:
	// Get metadata from ctx and request
	// Do resource inspect, permission inspect, type inspect, black list inspect
	switch checkType {
	case BASIC:
		user, resource, action, err := GetSecretData(ctx, req)
		if err != nil {
			return v1.ErrorInputArgError("Can not conver request type: %s", err)
		}

		err = auth.CheckSecretPermission(ctx, user, resource, action)
		if err != nil {
			return v1.ErrorActionNotAllow("This action is now allowed by current user: %s", err)
		}
	case GRANT:
		user, resource, destUser, err := getGrantData(ctx, req)
		if err != nil {
			return v1.ErrorInputArgError("Can not conver request type: %s", err)
		}
		err = auth.CheckGrantPermission(ctx, user, resource, destUser)
		if err != nil {
			return v1.ErrorActionNotAllow("This action is now allowed by current user: %s", err)
		}
	}
	return nil
}

func createBlackListACL(regexs []string) string {
	acl := ""
	for _, regex := range regexs {
		acl += fmt.Sprintf("p, RUNTIME, auth/%s/.*\n", regex)
	}
	return acl
}
