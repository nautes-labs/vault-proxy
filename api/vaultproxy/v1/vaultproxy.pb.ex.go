package v1

import (
	"bytes"
	fmt "fmt"
	"text/template"
)

const (
	GitSecretName     = "git"
	RepoSecretName    = "repo"
	ClusterSecretName = "cluster"
	TenantSecretName  = "tenant"
)

type SecretType int

const (
	GIT SecretType = iota
	REPO
	CLUSTER
	TENANTGIT
	TENANTREPO
)

func (s SecretType) String() string {
	switch s {
	case GIT:
		return "git"
	case REPO:
		return "repo"
	case CLUSTER:
		return "cluster"
	case TENANTGIT:
		return "tenant-git"
	case TENANTREPO:
		return "tenant-repo"
	}
	return ""
}

var (
	SecretPolicy string = "path \"%s\" {\n    capabilities = [\"read\"]\n}"
	GitPolicy    string = `
path "git/data/%[1]s" {
    capabilities = ["read"]
}

path "git/metadata/%[1]s" {
    capabilities = ["read"]
}`
	ClusterPolicy string = `
path "cluster/data/%s" {
    capabilities = ["read"]
}

path "auth/%s/role/*" {
    capabilities = ["read"]
}`
)

type VaultTemplate struct {
	name     string
	template string
}

var (
	GitPathTemplate VaultTemplate = VaultTemplate{
		name:     "gitPath",
		template: "{{.Providertype}}/{{.Repoid}}/{{.Username}}/{{.Permission}}",
	}
	GitPolicyPathTemplate VaultTemplate = VaultTemplate{
		name:     "gitPolicyPath",
		template: "{{.Providertype}}-{{.Repoid}}-{{.Username}}-{{.Permission}}",
	}
	RepoPathTemplate VaultTemplate = VaultTemplate{
		name:     "repoPath",
		template: "{{.Providerid}}/{{.Repotype}}/{{.Repoid}}/{{.Username}}/{{.Permission}}",
	}
	RepoPolicyPathTemplate VaultTemplate = VaultTemplate{
		name:     "repoPolicy",
		template: "{{.Providerid}}-{{.Repotype}}-{{.Repoid}}-{{.Username}}-{{.Permission}}",
	}
	ClusterPathTemplate VaultTemplate = VaultTemplate{
		name:     "clusterPath",
		template: "{{.Clustertype}}/{{.Clusterid}}/{{.Username}}/{{.Permission}}",
	}
	ClusterPolicyPathTemplate VaultTemplate = VaultTemplate{
		name:     "clusterPolicyPath",
		template: "{{.Clustertype}}-{{.Clusterid}}-{{.Username}}-{{.Permission}}",
	}
	TenantGitPathTemplate VaultTemplate = VaultTemplate{
		name:     "tenantGitPath",
		template: "git/{{.Id}}/{{.Permission}}",
	}
	TenantGitPolicyPathTemplate VaultTemplate = VaultTemplate{
		name:     "tenantGitPolicyPath",
		template: "tenant-git-{{.Id}}-{{.Permission}}",
	}
	TenantRepoPathTemplate VaultTemplate = VaultTemplate{
		name:     "tenantRepoPath",
		template: "repo/{{.Id}}/{{.Permission}}",
	}
	TenantRepoPolicyPathTemplate VaultTemplate = VaultTemplate{
		name:     "tenantRepoPolicyPath",
		template: "tenant-repo-{{.Id}}-{{.Permission}}",
	}
	RolePathTemplate = VaultTemplate{
		name:     "rolePath",
		template: "auth/{{.ClusterName}}/role/{{.Projectid}}",
	}
)

func GetPath(vars interface{}, vault_tmpl VaultTemplate) (string, error) {
	tmpl, err := template.New(vault_tmpl.name).Parse(vault_tmpl.template)
	if err != nil {
		return "", err
	}

	var path bytes.Buffer
	err = tmpl.ExecuteTemplate(&path, vault_tmpl.name, vars)
	if err != nil {
		return "", err
	}
	return path.String(), nil
}

func (x *GitAccount) getData() map[string]interface{} {
	return map[string]interface{}{
		x.GetAccesstype(): x.GetDeploykey(),
	}
}

func (x *RepoAccount) getData() map[string]interface{} {
	return map[string]interface{}{
		"username": x.GetUsername(),
		"password": x.GetPassword(),
	}
}

func (x *ClusterAccount) getData() map[string]interface{} {
	data := make(map[string]interface{})
	if x.GetCert() != nil {
		data["cert"] = x.GetCert().GetClientCert()
		data["key"] = x.GetCert().GetClientKey()
	}
	if x.GetOauth() != nil {
		data["username"] = x.GetOauth().GetUsername()
		data["password"] = x.GetOauth().GetPassword()
	}
	if x.GetToken() != "" {
		data["token"] = x.GetToken()
	}
	if x.GetKubeconfig() != "" {
		data["kubeconfig"] = x.GetKubeconfig()
	}
	return data
}

// Store the key info for authorize and vault request
type SecretRequest struct {
	SecretName string // secret name , use for vault api
	SecretPath string // secret path , use for vault api
	SecretType string // secret data type
	FullPath   string // full path of secret use for create policy and authorize
	PolicyName string // vault policy name, use for authorize and policy create
	SecretData map[string]interface{}
	PolicyData string
}

type SecRequest interface {
	ConvertRequest() (*SecretRequest, error)
}

func (x *GitRequest) ConvertRequest() (*SecretRequest, error) {
	var err error

	secretName := GitSecretName
	secretPath, err := GetPath(x, GitPathTemplate)
	if err != nil {
		return nil, err
	}
	fullPath := fmt.Sprintf("%s/data/%s", secretName, secretPath)
	policyName, err := GetPath(x, GitPolicyPathTemplate)
	if err != nil {
		return nil, err
	}
	secretData := make(map[string]interface{}, 0)
	for k, v := range x.AdditionalKVs {
		secretData[k] = v
	}
	for k, v := range x.GetAccount().getData() {
		secretData[k] = v
	}
	policyData := fmt.Sprintf(GitPolicy, secretPath)

	return &SecretRequest{
		SecretName: secretName,
		SecretPath: secretPath,
		SecretType: GIT.String(),
		FullPath:   fullPath,
		PolicyName: policyName,
		SecretData: secretData,
		PolicyData: policyData,
	}, nil
}

func (x *RepoRequest) ConvertRequest() (*SecretRequest, error) {
	var err error

	secretName := RepoSecretName
	secretPath, err := GetPath(x, RepoPathTemplate)
	if err != nil {
		return nil, err
	}
	fullPath := fmt.Sprintf("%s/data/%s", secretName, secretPath)
	policyName, err := GetPath(x, RepoPolicyPathTemplate)
	if err != nil {
		return nil, err
	}
	secretData := x.GetAccount().getData()
	policyData := fmt.Sprintf(SecretPolicy, fullPath)

	return &SecretRequest{
		SecretName: secretName,
		SecretPath: secretPath,
		SecretType: REPO.String(),
		FullPath:   fullPath,
		PolicyName: policyName,
		SecretData: secretData,
		PolicyData: policyData,
	}, nil
}

func (x *ClusterRequest) ConvertRequest() (*SecretRequest, error) {
	var err error

	secretName := ClusterSecretName
	secretPath, err := GetPath(x, ClusterPathTemplate)
	if err != nil {
		return nil, err
	}
	fullPath := fmt.Sprintf("%s/data/%s", secretName, secretPath)
	policyName, err := GetPath(x, ClusterPolicyPathTemplate)
	if err != nil {
		return nil, err
	}
	secretData := x.GetAccount().getData()
	policyData := fmt.Sprintf(ClusterPolicy, secretPath, x.GetClusterid())

	return &SecretRequest{
		SecretName: secretName,
		SecretPath: secretPath,
		SecretType: CLUSTER.String(),
		FullPath:   fullPath,
		PolicyName: policyName,
		SecretData: secretData,
		PolicyData: policyData,
	}, nil
}

func (x *TenantGitRequest) ConvertRequest() (*SecretRequest, error) {
	var err error

	secretName := TenantSecretName
	secretPath, err := GetPath(x, TenantGitPathTemplate)
	if err != nil {
		return nil, err
	}
	fullPath := fmt.Sprintf("%s/data/%s", secretName, secretPath)
	policyName, err := GetPath(x, TenantGitPolicyPathTemplate)
	if err != nil {
		return nil, err
	}
	secretData := x.GetAccount().getData()
	policyData := fmt.Sprintf(SecretPolicy, fullPath)

	return &SecretRequest{
		SecretName: secretName,
		SecretPath: secretPath,
		SecretType: TENANTGIT.String(),
		FullPath:   fullPath,
		PolicyName: policyName,
		SecretData: secretData,
		PolicyData: policyData,
	}, nil
}

func (x *TenantRepoRequest) ConvertRequest() (*SecretRequest, error) {
	var err error

	secretName := TenantSecretName
	secretPath, err := GetPath(x, TenantRepoPathTemplate)
	if err != nil {
		return nil, err
	}
	fullPath := fmt.Sprintf("%s/data/%s", secretName, secretPath)
	policyName, err := GetPath(x, TenantRepoPolicyPathTemplate)
	if err != nil {
		return nil, err
	}
	secretData := x.GetAccount().getData()
	policyData := fmt.Sprintf(SecretPolicy, fullPath)

	return &SecretRequest{
		SecretName: secretName,
		SecretPath: secretPath,
		SecretType: TENANTREPO.String(),
		FullPath:   fullPath,
		PolicyName: policyName,
		SecretData: secretData,
		PolicyData: policyData,
	}, nil
}

func (x *AuthRequest) ConvertRequest() (*SecretRequest, error) {

	fullPath := fmt.Sprintf("auth/%s", x.ClusterName)

	return &SecretRequest{
		SecretName: "",
		SecretPath: "",
		SecretType: "",
		FullPath:   fullPath,
		PolicyName: "",
		SecretData: nil,
		PolicyData: "",
	}, nil
}

func (x *AuthroleRequest) ConvertRequest() (*SecretRequest, error) {

	fullPath := fmt.Sprintf("auth/%s/role/%s", x.ClusterName, x.DestUser)

	return &SecretRequest{
		SecretName: "",
		SecretPath: "",
		SecretType: "",
		FullPath:   fullPath,
		PolicyName: "",
		SecretData: nil,
		PolicyData: "",
	}, nil
}

type GrantTarget struct {
	RolePath string
	Name     string
}

type AuthGrantRequest interface {
	ConvertToAuthPolicyReqeuest() (*GrantTarget, *SecretRequest, error)
}

func ConvertAuthGrantRequest(cluster, user string, sec SecRequest) (*GrantTarget, *SecretRequest, error) {
	rolePath, err := GetPath(map[string]string{"ClusterName": cluster, "Projectid": user}, RolePathTemplate)
	if err != nil {
		return nil, nil, err
	}

	secReq, err := sec.ConvertRequest()
	if err != nil {
		return nil, nil, err
	}

	return &GrantTarget{
		RolePath: rolePath,
		Name:     user,
	}, secReq, nil
}

func (req *AuthroleGitPolicyRequest) ConvertToAuthPolicyReqeuest() (*GrantTarget, *SecretRequest, error) {
	return ConvertAuthGrantRequest(req.ClusterName, req.DestUser, req.GetSecretOptions())
}

func (req *AuthroleRepoPolicyRequest) ConvertToAuthPolicyReqeuest() (*GrantTarget, *SecretRequest, error) {
	return ConvertAuthGrantRequest(req.ClusterName, req.DestUser, req.GetSecretOptions())
}

func (req *AuthroleClusterPolicyRequest) ConvertToAuthPolicyReqeuest() (*GrantTarget, *SecretRequest, error) {
	return ConvertAuthGrantRequest(req.ClusterName, req.DestUser, req.GetSecretOptions())
}

func (req *AuthroleTenantGitPolicyRequest) ConvertToAuthPolicyReqeuest() (*GrantTarget, *SecretRequest, error) {
	return ConvertAuthGrantRequest(req.ClusterName, req.DestUser, req.GetSecretOptions())
}

func (req *AuthroleTenantRepoPolicyRequest) ConvertToAuthPolicyReqeuest() (*GrantTarget, *SecretRequest, error) {
	return ConvertAuthGrantRequest(req.ClusterName, req.DestUser, req.GetSecretOptions())
}
