// Package keycloak 实现基于Keycloak REST API的操作模块
package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Role 表示Keycloak中的角色
type Role struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Composite   bool                   `json:"composite,omitempty"`
	ClientRole  bool                   `json:"clientRole,omitempty"`
	ContainerId string                 `json:"containerId,omitempty"`
	Attributes  map[string][]string    `json:"attributes,omitempty"`
	Composites  map[string]interface{} `json:"composites,omitempty"`
}

// RolesService 提供角色相关的API操作
type RolesService struct {
	client *KeycloakClient
	realm  string
}

// List 获取所有Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) List(ctx context.Context) ([]Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/roles", s.realm)

	var roles []Role
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

// Get 获取指定名称的Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) Get(ctx context.Context, roleName string) (*Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s", s.realm, roleName)

	var role Role
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}

// Create 创建新的Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) Create(ctx context.Context, role Role) error {
	path := fmt.Sprintf("/admin/realms/%s/roles", s.realm)
	return s.client.DoRequest(ctx, http.MethodPost, path, role, nil)
}

// Update 更新Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) Update(ctx context.Context, roleName string, role Role) error {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s", s.realm, roleName)
	return s.client.DoRequest(ctx, http.MethodPut, path, role, nil)
}

// Delete 删除Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) Delete(ctx context.Context, roleName string) error {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s", s.realm, roleName)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// AddComposite 添加复合角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) AddComposite(ctx context.Context, roleName string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s/composites", s.realm, roleName)
	return s.client.DoRequest(ctx, http.MethodPost, path, roles, nil)
}

// RemoveComposite 移除复合角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) RemoveComposite(ctx context.Context, roleName string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s/composites", s.realm, roleName)
	return s.client.DoRequest(ctx, http.MethodDelete, path, roles, nil)
}

// GetUsers 获取拥有指定角色的用户
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_roles_resource
func (s *RolesService) GetUsers(ctx context.Context, roleName string, params map[string]string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/roles/%s/users", s.realm, roleName)

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

// ClientRolesService 提供客户端角色相关的API操作
type ClientRolesService struct {
	client *KeycloakClient
	realm  string
}

// List 获取指定客户端的所有角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) List(ctx context.Context, clientID string) ([]Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles", s.realm, clientID)

	var roles []Role
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

// Get 获取指定客户端的指定角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) Get(ctx context.Context, clientID string, roleName string) (*Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", s.realm, clientID, roleName)

	var role Role
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}

// Create 创建客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) Create(ctx context.Context, clientID string, role Role) error {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles", s.realm, clientID)
	return s.client.DoRequest(ctx, http.MethodPost, path, role, nil)
}

// Update 更新客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) Update(ctx context.Context, clientID string, roleName string, role Role) error {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", s.realm, clientID, roleName)
	return s.client.DoRequest(ctx, http.MethodPut, path, role, nil)
}

// Delete 删除客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) Delete(ctx context.Context, clientID string, roleName string) error {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", s.realm, clientID, roleName)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// AddComposite 添加客户端复合角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) AddComposite(ctx context.Context, clientID string, roleName string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s/composites", s.realm, clientID, roleName)
	return s.client.DoRequest(ctx, http.MethodPost, path, roles, nil)
}

// RemoveComposite 移除客户端复合角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) RemoveComposite(ctx context.Context, clientID string, roleName string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s/composites", s.realm, clientID, roleName)
	return s.client.DoRequest(ctx, http.MethodDelete, path, roles, nil)
}

// GetUsers 获取拥有指定客户端角色的用户
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_role_mappings_resource
func (s *ClientRolesService) GetUsers(ctx context.Context, clientID string, roleName string, params map[string]string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s/users", s.realm, clientID, roleName)

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
