// Package keycloak 实现基于Keycloak REST API的操作模块
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Organization 表示Keycloak中的组织
type Organization struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name"`
	DisplayName string              `json:"displayName,omitempty"`
	Domains     []string            `json:"domains,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

// OrganizationsService 提供组织相关的API操作
type OrganizationsService struct {
	client *KeycloakClient
	realm  string
}

// List 获取组织列表
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) List(ctx context.Context, params map[string]string) ([]Organization, error) {
	path := fmt.Sprintf("/admin/realms/%s/orgs", s.realm)

	// 添加查询参数
	if len(params) > 0 {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		path = path + "?" + query.Encode()
	}

	var orgs []Organization
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &orgs)
	return orgs, err
}

// Get 获取指定ID的组织
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) Get(ctx context.Context, orgID string) (*Organization, error) {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s", s.realm, orgID)

	var org Organization
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &org)
	return &org, err
}

// Create 创建新组织
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) Create(ctx context.Context, org Organization) (string, error) {
	path := fmt.Sprintf("/admin/realms/%s/orgs", s.realm)

	// 发送请求并获取Location头
	token, err := s.client.getValidToken(ctx)
	if err != nil {
		return "", fmt.Errorf("获取有效令牌失败: %w", err)
	}

	url := s.client.BaseURL + path
	data, err := json.Marshal(org)
	if err != nil {
		return "", fmt.Errorf("序列化组织数据失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errorResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return "", fmt.Errorf("创建组织失败，状态码: %d", resp.StatusCode)
		}
		return "", fmt.Errorf("创建组织失败，状态码: %d, 错误: %v", resp.StatusCode, errorResp)
	}

	// 从Location头中提取组织ID
	location := resp.Header.Get("Location")
	parts := strings.Split(location, "/")
	orgID := parts[len(parts)-1]

	return orgID, nil
}

// Update 更新组织信息
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) Update(ctx context.Context, orgID string, org Organization) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s", s.realm, orgID)
	return s.client.DoRequest(ctx, http.MethodPut, path, org, nil)
}

// Delete 删除组织
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) Delete(ctx context.Context, orgID string) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s", s.realm, orgID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// AddDomain 为组织添加域名
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) AddDomain(ctx context.Context, orgID string, domain string) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/domains/%s", s.realm, orgID, domain)
	return s.client.DoRequest(ctx, http.MethodPost, path, nil, nil)
}

// RemoveDomain 从组织移除域名
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) RemoveDomain(ctx context.Context, orgID string, domain string) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/domains/%s", s.realm, orgID, domain)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// ListMembers 获取组织成员
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) ListMembers(ctx context.Context, orgID string, params map[string]string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/members", s.realm, orgID)

	// 添加查询参数
	if len(params) > 0 {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		path = path + "?" + query.Encode()
	}

	var users []User
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

// AddMember 将用户添加到组织
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) AddMember(ctx context.Context, orgID string, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/members/%s", s.realm, orgID, userID)
	return s.client.DoRequest(ctx, http.MethodPost, path, nil, nil)
}

// RemoveMember 将用户从组织中移除
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) RemoveMember(ctx context.Context, orgID string, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/members/%s", s.realm, orgID, userID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// ListRoles 获取组织角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) ListRoles(ctx context.Context, orgID string) ([]Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/roles", s.realm, orgID)

	var roles []Role
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

// CreateRole 创建组织角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) CreateRole(ctx context.Context, orgID string, role Role) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/roles", s.realm, orgID)
	return s.client.DoRequest(ctx, http.MethodPost, path, role, nil)
}

// GetRole 获取组织角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) GetRole(ctx context.Context, orgID string, roleName string) (*Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/roles/%s", s.realm, orgID, roleName)

	var role Role
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}

// UpdateRole 更新组织角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) UpdateRole(ctx context.Context, orgID string, roleName string, role Role) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/roles/%s", s.realm, orgID, roleName)
	return s.client.DoRequest(ctx, http.MethodPut, path, role, nil)
}

// DeleteRole 删除组织角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_organizations_resource
func (s *OrganizationsService) DeleteRole(ctx context.Context, orgID string, roleName string) error {
	path := fmt.Sprintf("/admin/realms/%s/orgs/%s/roles/%s", s.realm, orgID, roleName)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}
