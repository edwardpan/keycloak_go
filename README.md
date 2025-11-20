# Keycloak 操作模块

本模块提供基于Keycloak REST API的操作功能，用于远程控制Keycloak中的数据，包括用户、组、角色、客户端角色和组织等资源的管理。

## 功能特性

- 基于Keycloak REST API实现完整的资源管理
- 支持OpenID Connect认证流程
- 自动处理令牌刷新和过期
- 按API类型分目录组织代码
- 提供友好的服务获取接口
- 详细的中文注释和文档引用

## 模块结构

```
keycloak/
├── keycloak.go      # 核心客户端实现，包含认证和HTTP请求处理
├── users.go         # 用户管理API
├── groups.go        # 组管理API
├── roles.go         # 角色管理API（包含客户端角色）
├── organizations.go # 组织管理API
└── example/         # 使用示例
```

## 快速开始

### 初始化客户端

```go
// 创建Keycloak客户端实例
client, err := keycloak.New(
    "http://keycloak.example.com/auth/", // Keycloak服务器地址
    "admin",                            // 用户名
    "password",                         // 密码
    keycloak.WithClientID("admin-cli"),  // 可选：设置客户端ID
    keycloak.WithMasterRealm("master"),  // 可选：设置主Realm
    keycloak.WithTimeout(10*time.Second), // 可选：设置超时
)
if err != nil {
    // 处理错误
}
```

### 用户管理

```go
// 获取用户服务，指定要操作的realm
userService := client.GetUsersService("my-realm")

// 创建用户
newUser := keycloak.User{
    Username:      "test-user",
    Enabled:       true,
    EmailVerified: true,
    FirstName:     "Test",
    LastName:      "User",
    Email:         "test@example.com",
}

userID, err := userService.Create(ctx, newUser)

// 设置用户密码
err = userService.SetPassword(ctx, userID, "password123", false)

// 查询用户
users, err := userService.List(ctx, map[string]string{
    "username": "test",
    "max":      "10",
})
```

### 角色管理

```go
// 获取角色服务
rolesService := client.GetRolesService("my-realm")

// 创建角色
newRole := keycloak.Role{
    Name:        "app-user",
    Description: "应用普通用户",
}

err = rolesService.Create(ctx, newRole)

// 为用户分配角色
role, err := rolesService.Get(ctx, "app-user")
if err == nil {
    err = userService.AddRealmRole(ctx, userID, []keycloak.Role{*role})
}
```

### 组管理

```go
// 获取组服务
groupsService := client.GetGroupsService("my-realm")

// 创建组
newGroup := keycloak.Group{
    Name: "users-group",
    Attributes: map[string][]string{
        "description": {"用户组"},
    },
}

groupID, err := groupsService.Create(ctx, newGroup)

// 将用户添加到组
err = userService.AddToGroup(ctx, userID, groupID)
```

### 组织管理

```go
// 获取组织服务
orgsService := client.GetOrganizationsService("my-realm")

// 创建组织
newOrg := keycloak.Organization{
    Name:        "my-org",
    DisplayName: "我的组织",
    Domains:     []string{"example.com"},
}

orgID, err := orgsService.Create(ctx, newOrg)

// 将用户添加到组织
err = orgsService.AddMember(ctx, orgID, userID)
```

## 完整示例

请参考 `example/example.go` 文件，其中包含了完整的使用示例。

## 注意事项

1. 使用前需确保Keycloak服务器已正确配置并可访问
2. 提供的账号需要有足够的权限执行相应操作
3. 默认使用master realm进行认证，操作其他realm时需要指定
4. 所有API操作都需要提供context参数，用于传递上下文和取消信号