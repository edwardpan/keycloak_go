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

// Group 表示Keycloak中的组
type Group struct {
	ID            string              `json:"id,omitempty"`
	Name          string              `json:"name"`
	Description   string              `json:"description,omitempty"`
	Path          string              `json:"path,omitempty"`
	ParentId      string              `json:"parentId,omitempty"`
	SubGroupCount int                 `json:"subGroupCount,omitempty"`
	SubGroups     []Group             `json:"subGroups,omitempty"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	RealmRoles    []string            `json:"realmRoles,omitempty"`
	ClientRoles   map[string][]string `json:"clientRoles,omitempty"`
	Access        map[string]bool     `json:"access,omitempty"`
}

// GroupsService 提供组相关的API操作
type GroupsService struct {
	client *KeycloakClient
	realm  string
}

// Count 获取组数量
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) Count(ctx context.Context, params map[string]string) (int, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/count", s.realm)

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

// List 获取组列表
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) List(ctx context.Context, params map[string]string) ([]Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups", s.realm)

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

// Get 获取指定ID的组
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) Get(ctx context.Context, groupID string) (*Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", s.realm, groupID)

	var group Group
	err := s.client.DoRequest(ctx, http.MethodGet, path, nil, &group)
	return &group, err
}

// Create 创建新组
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) Create(ctx context.Context, group Group) (string, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups", s.realm)

	// 发送请求并获取Location头
	token, err := s.client.getValidToken(ctx)
	if err != nil {
		return "", fmt.Errorf("获取有效令牌失败: %w", err)
	}

	url := s.client.BaseURL + path
	data, err := json.Marshal(group)
	if err != nil {
		return "", fmt.Errorf("序列化组数据失败: %w", err)
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
			return "", fmt.Errorf("创建组失败，状态码: %d", resp.StatusCode)
		}
		return "", fmt.Errorf("创建组失败，状态码: %d, 错误: %v", resp.StatusCode, errorResp)
	}

	// 从Location头中提取组ID
	location := resp.Header.Get("Location")
	parts := strings.Split(location, "/")
	groupID := parts[len(parts)-1]

	return groupID, nil
}

// ListSubGroup 获取子组列表
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) ListSubGroup(ctx context.Context, groupID string, params map[string]string) ([]Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/children", s.realm, groupID)

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

// CreateSubGroup 创建子组
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) CreateSubGroup(ctx context.Context, parentID string, group Group) (string, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/children", s.realm, parentID)

	// 发送请求并获取Location头
	token, err := s.client.getValidToken(ctx)
	if err != nil {
		return "", fmt.Errorf("获取有效令牌失败: %w", err)
	}

	url := s.client.BaseURL + path
	data, err := json.Marshal(group)
	if err != nil {
		return "", fmt.Errorf("序列化组数据失败: %w", err)
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

	if resp.StatusCode == http.StatusNoContent && group.ID != "" {
		// 是移动子组的父级
		return group.ID, nil
	}

	if resp.StatusCode != http.StatusCreated {
		var errorResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return "", fmt.Errorf("创建子组失败，状态码: %d", resp.StatusCode)
		}
		return "", fmt.Errorf("创建子组失败，状态码: %d, 错误: %v", resp.StatusCode, errorResp)
	}

	// 从Location头中提取组ID
	location := resp.Header.Get("Location")
	parts := strings.Split(location, "/")
	groupID := parts[len(parts)-1]

	return groupID, nil
}

// Update 更新组信息
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) Update(ctx context.Context, groupID string, group Group) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", s.realm, groupID)
	return s.client.DoRequest(ctx, http.MethodPut, path, group, nil)
}

// Delete 删除组
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) Delete(ctx context.Context, groupID string) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", s.realm, groupID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, nil, nil)
}

// ListMembers 获取组成员
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) ListMembers(ctx context.Context, groupID string, params map[string]string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/members", s.realm, groupID)

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

// AddRealmRole 为组分配Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) AddRealmRole(ctx context.Context, groupID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/realm", s.realm, groupID)
	return s.client.DoRequest(ctx, http.MethodPost, path, roles, nil)
}

// RemoveRealmRole 移除组的Realm角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) RemoveRealmRole(ctx context.Context, groupID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/realm", s.realm, groupID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, roles, nil)
}

// AddClientRole 为组分配客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) AddClientRole(ctx context.Context, groupID string, clientID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/clients/%s", s.realm, groupID, clientID)
	return s.client.DoRequest(ctx, http.MethodPost, path, roles, nil)
}

// RemoveClientRole 移除组的客户端角色
// 文档: https://www.keycloak.org/docs-api/latest/rest-api/index.html#_groups_resource
func (s *GroupsService) RemoveClientRole(ctx context.Context, groupID string, clientID string, roles []Role) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/clients/%s", s.realm, groupID, clientID)
	return s.client.DoRequest(ctx, http.MethodDelete, path, roles, nil)
}
