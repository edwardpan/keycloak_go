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

// User 表示Keycloak中的用户
type User struct {
	ID                         string                 `json:"id,omitempty"`
	CreatedTimestamp           int64                  `json:"createdTimestamp,omitempty"`
	Username                   string                 `json:"username,omitempty"`
	Enabled                    bool                   `json:"enabled"`
	Totp                       bool                   `json:"totp,omitempty"`
	EmailVerified              bool                   `json:"emailVerified"`
	FirstName                  string                 `json:"firstName,omitempty"`
	LastName                   string                 `json:"lastName,omitempty"`
	Email                      string                 `json:"email,omitempty"`
	DisableableCredentialTypes []string               `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            []string               `json:"requiredActions,omitempty"`
	NotBefore                  int                    `json:"notBefore,omitempty"`
	Access                     map[string]bool        `json:"access,omitempty"`
	Attributes                 map[string][]string    `json:"attributes,omitempty"`
	ClientRoles                map[string]interface{} `json:"clientRoles,omitempty"`
	Groups                     []string               `json:"groups,omitempty"`
	RealmRoles                 []string               `json:"realmRoles,omitempty"`
	ServiceAccountClientID     string                 `json:"serviceAccountClientId,omitempty"`
	Credentials                []Credential           `json:"credentials,omitempty"`
}

// Credential 表示用户凭证
type Credential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// UsersService 提供用户相关的API操作
type UsersService struct {
	client *KeycloakClient
	realm  string
}

// List 获取用户列表
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) List(ctx context.Context, params map[string]string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users", s.realm)

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

func (s *UsersService) Count(ctx context.Context, params map[string]string) (int, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/count", s.realm)

	// 添加查询参数
	if len(params) > 0 {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		path = path + "?" + query.Encode()
	}

	var count int
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &count)
	return count, err
}

// Get 获取指定ID的用户
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) Get(ctx context.Context, userID string, params map[string]string) (*User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", s.realm, userID)

	// 添加查询参数
	if len(params) > 0 {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		path = path + "?" + query.Encode()
	}

	var user User
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &user)
	return &user, err
}

// Create 创建新用户
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) Create(ctx context.Context, user User) (string, error) {
	path := fmt.Sprintf("/admin/realms/%s/users", s.realm)

	// 发送请求并获取Location头
	token, err := s.client.getValidToken(ctx)
	if err != nil {
		return "", fmt.Errorf("获取有效令牌失败: %w", err)
	}

	url := s.client.BaseURL + path
	data, err := json.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("序列化用户数据失败: %w", err)
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
			return "", fmt.Errorf("创建用户失败，状态码: %d", resp.StatusCode)
		}
		return "", fmt.Errorf("创建用户失败，状态码: %d, 错误: %v", resp.StatusCode, errorResp)
	}

	// 从Location头中提取用户ID
	location := resp.Header.Get("Location")
	parts := strings.Split(location, "/")
	userID := parts[len(parts)-1]

	return userID, nil
}

// Update 更新用户信息
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) Update(ctx context.Context, userID string, user User) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", s.realm, userID)
	return s.client.DoRequest(ctx, http.MethodPut, path, user, nil)
}

// Delete 删除用户
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) Delete(ctx context.Context, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", s.realm, userID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// SetPassword 设置用户密码
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) SetPassword(ctx context.Context, userID string, password string, temporary bool) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/reset-password", s.realm, userID)

	credential := Credential{
		Type:      "password",
		Value:     password,
		Temporary: temporary,
	}

	return s.client.DoRequest(ctx, http.MethodPut, path, credential, nil)
}

// AddToGroup 将用户添加到组
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) AddToGroup(ctx context.Context, userID string, groupID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups/%s", s.realm, userID, groupID)
	return s.client.DoRequest(ctx, http.MethodPut, path, nil, nil)
}

// RemoveFromGroup 将用户从组中移除
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) RemoveFromGroup(ctx context.Context, userID string, groupID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups/%s", s.realm, userID, groupID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// CountGroups 获取用户所属的组数量
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) CountGroups(ctx context.Context, userID string, params map[string]string) (int, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups/count", s.realm, userID)

	// 添加查询参数
	if len(params) > 0 {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		path = path + "?" + query.Encode()
	}

	var json map[string]interface{}
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &json)
	return int(json["count"].(float64)), err
}

// ListGroups 获取用户所属的组
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) ListGroups(ctx context.Context, userID string, params map[string]string) ([]Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups", s.realm, userID)

	// 添加查询参数
	if len(params) > 0 {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		path = path + "?" + query.Encode()
	}

	var groups []Group
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &groups)
	return groups, err
}

// AddRealmRole 为用户分配Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) AddRealmRole(ctx context.Context, userID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", s.realm, userID)
	return s.client.DoRequest(ctx, http.MethodPost, path, roles, nil)
}

// RemoveRealmRole 移除用户的Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) RemoveRealmRole(ctx context.Context, userID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", s.realm, userID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, roles, nil)
}

// AddClientRole 为用户分配客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) AddClientRole(ctx context.Context, userID string, clientID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/clients/%s", s.realm, userID, clientID)
	return s.client.DoRequest(ctx, http.MethodPost, path, roles, nil)
}

// RemoveClientRole 移除用户的客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource
func (s *UsersService) RemoveClientRole(ctx context.Context, userID string, clientID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/clients/%s", s.realm, userID, clientID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, roles, nil)
}

func (s *UsersService) Logout(ctx context.Context, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/logout", s.realm, userID)
	return s.client.DoRequest(ctx, http.MethodPost, path, nil, nil)
}
