# Vault Proxy
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![golang](https://img.shields.io/badge/golang-v1.20.0-brightgreen)](https://go.dev/doc/install)
[![version](https://img.shields.io/badge/version-v0.3.2-green)]()

Vault Proxy 项目是对开源版 [Vault](https://github.com/hashicorp/vault) 的增删改接口的封装，提供了更细粒度的权限控制。本项目的所有接口均是应用于 Nautes 的其他管理组件，暂不支持通用的增强 Vault 权限控制的需求。

项目提供了以下类型的数据的存储接口。
| 类型 | 说明 | 备注 |
| --- | --- | --- |
| cluster | 计算集群的访问密钥 | 目前只支持 Kubernetes 集群 |
| git | 代码库的访问密钥 |目前只支持 GitLab|
| pki | SSL 证书的公钥 |目前只支持 Nautes 自签证书的公钥|
| repo | 制品库的访问密钥 |目前只支持 Harbor 和 Nexus|
| tenant | 代码库全局元数据只读密钥、制品库的全局访问密钥 |仅对 Nautes 的管理组件开放权限|

## 功能简介

Vault Proxy 会与 Vault 被部署到相同的安全单元（如一个服务器或一个 POD ）内，Vault Proxy 通过安全单元的内部 IP 和 AppRole 的认证方式访问 Vault。

Vault 只对安全单元内的 Vault Proxy 开放写权限，对外则只开放读权限。

其他管理组件需要修改 Vault 中的密钥、认证、权限等时必须调用 Vault Proxy 的接口，需要查询密钥数据时则直接调用 Vault 的接口。

为了保证 Vault Proxy 可以正常工作，Vault 中需要存在一个关联以下策略的 AppRole：
```json
path "sys/policies/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "patch", "delete", "list"]
}

path "tenant/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "git/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "repo/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "cluster/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "pki/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "auth/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}
```

### 认证与鉴权

Vault Proxy 为 Nautes 中所有的管理组件各自签发一个客户端证书，并通过该证书进行客户端请求的认证和身份信息的识别。

签发客户端证书示例：

```ini
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
C = CN
ST = GUANGDONG
L = SHENZHEN
O = LANBING
OU = NAUTES
CN = RUNTIME

[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
```

Vault 是通过 Casbin 进行权限建模，模型定义了组件对资源的操作权限、以及组件对组件的授权权限，定义权限的文件放在 configs/casbin 目录下：

- permission_acl.csv：[A组件] [是否可以] 授权 [X资源] 的只读权限给 [B组件]
- resource_acl.csv：[A组件] 是否对 [X资源] 有 [增|删|改] 权限

### API 实例

#### 创建密钥

Vault Proxy 在 Vault 中创建密钥时会同时创建一个只包含该密钥只读权限的策略。

下面的请求会在 Vault 中创建一个密钥：`git/gitlab/repo-64/default/readonly `和一个策略：`git-gitlab-repo-64-default-readonly`：

```shell
VAULT_PROXY_URL=127.0.0.1:8000

curl -X 'POST' \
  --cert ./apiserver.crt \
  --key ./apiserver.key \
  --cacert ./ca.crt \
  "HTTPS://${VAULT_PROXY_URL}/v1/git" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "providertype": "gitlab",
  "repoid": "repo-64",
  "username": "default",
  "permission": "readonly",
  "secretname": "git"
  "account": {
    "deploykey": "this_is_deploy_key",
    "accesstype": "deploykey"
  },
}'
```

#### 创建认证

Vault Proxy 目前只支持创建 [Kubernetes 认证](https://developer.hashicorp.com/vault/docs/auth/kubernetes)。

下面的请求会在 Vault 中创建一个 Kubernetes 认证，并在认证中为一个客户端组件创建角色：

```shell
VAULT_PROXY_URL=127.0.0.1:8000
AUTH_NAME=kubernetes
DEST_USER=RUNTIME

# This is a fake token, vault api require a jwt format token
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjpbeyJ0b29sdHQiOiJodHRwczovL3Rvb2x0dC5jb20ifV0sImlhdCI6MTY4MTQ0MDUzMSwiZXhwIjoxNjgxNDQwMDk0LCJhdWQiOiJ2YXVsdCIsImlzcyI6Im5hdXRlcyIsInN1YiI6IiJ9._eZMllr0yXbrt_2fk9V7CdBmejhtpepIgVoIk2GUrAg

# Create a kubernetes auth
curl -X 'POST' \
  --cert ./cluster.crt \
  --key ./cluster.key \
  --cacert ./ca.crt \
  "HTTPS://${VAULT_PROXY_URL}/v1/auth" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "clusterName": '\"${AUTH_NAME}\"',
  "authType": "kubernetes",
  "kubernetes": {
    "url": "https://127.0.0.1:6443",
    "cabundle": "@./ca/ca.crt",
    "usertoken": '\"$JWT\"'
  }
}'

# Create role on it
curl -X 'POST' \
  --cert ./cluster.crt \
  --key ./cluster.key \
  --cacert ./ca.crt \
  "HTTPS://${VAULT_PROXY_URL}/v1/auth/${AUTH_NAME}/role" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "destUser": '\"${DEST_USER}\"',
  "k8s": {
    "namespaces": "default",
    "serviceaccounts": "default"
  }
}'

```

#### 授权

Vault Proxy 的授权功能，是在 Kubernetes 认证中的代表某个客户端组件的角色上关联指定密钥对应的策略。

下面的请求是授予 Runtime Operator 查询代码库 repo-64 的 deploykey 的权限。

```shell
VAULT_PROXY_URL=127.0.0.1:8000
AUTH_NAME=kubernetes
DEST_USER=RUNTIME

curl -X 'POST' \
  --cert ./apiserver.crt \
  --key ./apiserver.key \
  --cacert ./ca.crt \
  "HTTPS://${VAULT_PROXY_URL}/v1/auth/${AUTH_NAME}/role/${DEST_USER}/policies/git" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "secretOptions": {
    "providertype": "gitlab",
    "repoid": "repo-64",
    "username": "default",
    "permission": "readonly",
    "secretname": "git"
  }
}'

```

## API 文档

如果您是在本地启动 Vault Proxy 的服务，可以通过下面的地址访问 swagger-ui 风格的 API 文档。

```shell
https://$api-server:$port/q/swagger-ui
```

## 快速开始

### 准备

安装以下工具，并配置 GOBIN 环境变量：

- [go](https://golang.org/dl/)
- [protoc](https://github.com/protocolbuffers/protobuf)
- [protoc-gen-go](https://github.com/protocolbuffers/protobuf-go)
- [kratos](https://go-kratos.dev/docs/getting-started/usage/#%E5%AE%89%E8%A3%85)

### 构建

```
make build
```

### 运行

```bash
kratos run
```
### 单元测试

```shell
go test -v ./...
```
