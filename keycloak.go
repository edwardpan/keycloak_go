// Package keycloak 实现基于Keycloak REST API的操作模块
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenResponse 表示从Keycloak获取的令牌响应
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// KeycloakClient 是Keycloak API的客户端
type KeycloakClient struct {
	BaseURL     string
	Username    string
	Password    string
	ClientID    string
	MasterRealm string
	HttpClient  *http.Client

	token       *TokenResponse
	tokenExpiry time.Time
	tokenLock   sync.RWMutex
	Logger      slog.Logger
}

// KeycloakOptions 配置Keycloak客户端的选项
type KeycloakOptions struct {
	// 必需，Keycloak服务器的基础URL
	BaseURL string

	// 必需，用于登录的用户名
	Username string

	// 必需，用于登录的密码
	Password string

	// 可选，用于登录的客户端ID，默认为"admin-cli"
	ClientID string

	// 可选，用于登录的主Realm，默认为"master"
	MasterRealm string

	// 可选，HTTP客户端超时设置，默认为10秒
	Timeout time.Duration

	// 可选，日志记录器
	Logger slog.Logger
}

// Option 是Keycloak客户端的配置选项
type Option func(o *KeycloakOptions)

// WithClientID 设置客户端ID
func WithClientID(clientID string) Option {
	return func(o *KeycloakOptions) { o.ClientID = clientID }
}

// WithMasterRealm 设置主Realm
func WithMasterRealm(realm string) Option {
	return func(o *KeycloakOptions) { o.MasterRealm = realm }
}

// WithTimeout 设置HTTP客户端超时
func WithTimeout(timeout time.Duration) Option {
	return func(o *KeycloakOptions) { o.Timeout = timeout }
}

// WithLogger 设置日志记录器
func WithLogger(logger slog.Logger) Option {
	return func(o *KeycloakOptions) { o.Logger = logger }
}

// New 创建一个新的Keycloak客户端
func New(baseURL, username, password string, opts ...Option) (*KeycloakClient, error) {
	options := &KeycloakOptions{
		BaseURL:     baseURL,
		Username:    username,
		Password:    password,
		ClientID:    "admin-cli",
		MasterRealm: "master",
		Timeout:     10 * time.Second,
		Logger:      *slog.With(),
	}

	for _, opt := range opts {
		opt(options)
	}

	// 验证必需的选项
	if options.BaseURL == "" {
		return nil, fmt.Errorf("baseURL不能为空")
	}
	if options.Username == "" {
		return nil, fmt.Errorf("username不能为空")
	}
	if options.Password == "" {
		return nil, fmt.Errorf("password不能为空")
	}

	// 确保baseURL不以/结尾
	if strings.HasSuffix(options.BaseURL, "/") {
		options.BaseURL = strings.TrimSuffix(options.BaseURL, "/")
	}

	client := &KeycloakClient{
		BaseURL:     options.BaseURL,
		Username:    options.Username,
		Password:    options.Password,
		ClientID:    options.ClientID,
		MasterRealm: options.MasterRealm,
		HttpClient:  &http.Client{Timeout: options.Timeout},
		Logger:      options.Logger,
	}

	// 初始化时获取令牌
	if err := client.authenticate(context.Background()); err != nil {
		return nil, fmt.Errorf("初始化Keycloak客户端失败: %w", err)
	}

	return client, nil
}

// authenticate 通过Keycloak的OpenID Connect进行身份验证
func (c *KeycloakClient) authenticate(ctx context.Context) error {
	c.tokenLock.Lock()
	defer c.tokenLock.Unlock()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.BaseURL, c.MasterRealm)

	data := url.Values{}
	data.Set("username", c.Username)
	data.Set("password", c.Password)
	data.Set("grant_type", "password")
	data.Set("client_id", c.ClientID)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("创建认证请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送认证请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("认证失败，状态码: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("解析令牌响应失败: %w", err)
	}

	c.Logger.Debug("通过认证获取到令牌, 过期时间: %d", tokenResp.ExpiresIn)
	c.token = &tokenResp
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-30) * time.Second) // 提前30秒刷新

	return nil
}

// refreshToken 使用刷新令牌获取新的访问令牌
func (c *KeycloakClient) refreshToken(ctx context.Context) error {
	c.tokenLock.Lock()
	defer c.tokenLock.Unlock()

	if c.token == nil || c.token.RefreshToken == "" {
		return fmt.Errorf("刷新令牌失败，刷新令牌为空")
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.BaseURL, c.MasterRealm)

	data := url.Values{}
	data.Set("refresh_token", c.token.RefreshToken)
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", c.ClientID)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("创建刷新令牌请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送刷新令牌请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 刷新令牌失败，尝试重新认证
		return fmt.Errorf("刷新令牌失败，应重新认证")
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("解析刷新令牌响应失败: %w", err)
	}

	c.Logger.Debug("通过刷新获取到令牌, 过期时间: %d", tokenResp.ExpiresIn)
	c.token = &tokenResp
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-30) * time.Second) // 提前30秒刷新

	return nil
}

// getValidToken 获取有效的访问令牌，如果令牌过期则刷新
func (c *KeycloakClient) getValidToken(ctx context.Context) (string, error) {
	c.tokenLock.RLock()
	if c.token != nil && time.Now().Before(c.tokenExpiry) {
		token := c.token.AccessToken
		c.tokenLock.RUnlock()
		return token, nil
	}
	c.tokenLock.RUnlock()

	// 令牌过期，需要刷新
	if err := c.refreshToken(ctx); err != nil {
		c.Logger.Warn("刷新令牌失败: %v", err)

		// 刷新失败，重新认证
		authenticateErr := c.authenticate(ctx)
		if authenticateErr != nil {
			return "", fmt.Errorf("重新认证失败: %w", authenticateErr)
		}
	}

	c.tokenLock.RLock()
	defer c.tokenLock.RUnlock()
	return c.token.AccessToken, nil
}

// DoRequest 执行HTTP请求，自动处理认证和令牌刷新
func (c *KeycloakClient) DoRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	token, err := c.getValidToken(ctx)
	if err != nil {
		return fmt.Errorf("获取有效令牌失败: %w", err)
	}

	// 确保path以/开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	url := c.BaseURL + path
	var reqBody *bytes.Buffer
	var req *http.Request
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("序列化请求体失败: %w", err)
		}
		reqBody = bytes.NewBuffer(data)
		req, err = http.NewRequestWithContext(ctx, method, url, reqBody)
	} else {
		// 当body为nil时，直接传入nil而不是nil的bytes.Buffer
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}

	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// 令牌可能已过期，尝试刷新
		if err := c.refreshToken(ctx); err != nil {
			return fmt.Errorf("刷新令牌失败: %w", err)
		}

		// 使用新令牌重试请求
		token, err = c.getValidToken(ctx)
		if err != nil {
			return fmt.Errorf("获取有效令牌失败: %w", err)
		}

		req, err = http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return fmt.Errorf("创建重试请求失败: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err = c.HttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("发送重试请求失败: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errorResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("请求失败，状态码: %d", resp.StatusCode)
		}
		return fmt.Errorf("请求失败，状态码: %d, 错误: %v", resp.StatusCode, errorResp)
	}

	if result != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("解析响应失败: %w", err)
		}
	}

	return nil
}

// GetUsersService 获取用户服务
func (c *KeycloakClient) GetUsersService(realm string) *UsersService {
	return &UsersService{client: c, realm: realm}
}

// GetGroupsService 获取组服务
func (c *KeycloakClient) GetGroupsService(realm string) *GroupsService {
	return &GroupsService{client: c, realm: realm}
}

// GetRolesService 获取角色服务
func (c *KeycloakClient) GetRolesService(realm string) *RolesService {
	return &RolesService{client: c, realm: realm}
}

// GetClientRolesService 获取客户端角色服务
func (c *KeycloakClient) GetClientRolesService(realm string) *ClientRolesService {
	return &ClientRolesService{client: c, realm: realm}
}

// GetOrganizationsService 获取组织服务
func (c *KeycloakClient) GetOrganizationsService(realm string) *OrganizationsService {
	return &OrganizationsService{client: c, realm: realm}
}
