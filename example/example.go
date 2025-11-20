// Package example 提供Keycloak模块使用示例
package example

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	keycloak "github.com/edwardpan/keycloak_go"
)

// ExampleKeycloakUsage 展示如何使用Keycloak模块
func ExampleKeycloakUsage() {
	ctx := context.Background()

	// 初始化Keycloak客户端
	baseURL := "http://keycloak.example.com/auth/"
	username := "admin"
	password := "password"

	// 创建Keycloak客户端实例
	client, err := keycloak.New(
		baseURL,
		username,
		password,
		keycloak.WithClientID("admin-cli"),
		keycloak.WithMasterRealm("master"),
		keycloak.WithTimeout(10*time.Second),
		keycloak.WithLogger(*slog.With()),
	)
	if err != nil {
		slog.Error("初始化Keycloak客户端失败: %v", err)
	}

	// 设置要操作的realm
	realm := "test"

	// 用户管理示例
	userService := client.GetUsersService(realm)

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
	if err != nil {
		slog.Error("创建用户失败: %v", err)
	} else {
		slog.Info("创建用户成功，ID: %s", userID)

		// 设置用户密码
		err = userService.SetPassword(ctx, userID, "password123", false)
		if err != nil {
			slog.Error("设置用户密码失败: %v", err)
		}
	}

	// 查询用户
	users, err := userService.List(ctx, map[string]string{
		"username": "test",
		"max":      "10",
	})
	if err != nil {
		slog.Error("查询用户失败: %v", err)
	} else {
		slog.Info("查询到 %d 个用户", len(users))
		for _, user := range users {
			slog.Info("用户: %s (%s %s)", user.Username, user.FirstName, user.LastName)
		}
	}

	// 角色管理示例
	rolesService := client.GetRolesService(realm)

	// 创建角色
	newRole := keycloak.Role{
		Name:        "role1",
		Description: "可以操作的角色",
	}

	err = rolesService.Create(ctx, newRole)
	if err != nil {
		slog.Error("创建角色失败: %v", err)
	} else {
		slog.Info("创建角色成功")
	}

	// 查询角色
	roles, err := rolesService.List(ctx)
	if err != nil {
		slog.Error("查询角色失败: %v", err)
	} else {
		slog.Info("查询到 %d 个角色", len(roles))
		for _, role := range roles {
			slog.Info("角色: %s (%s)", role.Name, role.Description)
		}
	}

	// 为用户分配角色
	if userID != "" {
		role, err := rolesService.Get(ctx, "role1")
		if err != nil {
			slog.Error("获取角色失败: %v", err)
		} else {
			err = userService.AddRealmRole(ctx, userID, []keycloak.Role{*role})
			if err != nil {
				slog.Error("为用户分配角色失败: %v", err)
			} else {
				slog.Info("为用户分配角色成功")
			}
		}
	}

	// 组管理示例
	groupsService := client.GetGroupsService(realm)

	// 创建组
	newGroup := keycloak.Group{
		Name: "team1",
		Attributes: map[string][]string{
			"description": {"可以操作的团队"},
		},
	}

	groupID, err := groupsService.Create(ctx, newGroup)
	if err != nil {
		slog.Error("创建组失败: %v", err)
	} else {
		slog.Info("创建组成功，ID: %s", groupID)

		// 将用户添加到组
		if userID != "" {
			err = userService.AddToGroup(ctx, userID, groupID)
			if err != nil {
				slog.Error("将用户添加到组失败: %v", err)
			} else {
				slog.Info("将用户添加到组成功")
			}
		}
	}

	// 组织管理示例
	orgsService := client.GetOrganizationsService(realm)

	// 创建组织
	newOrg := keycloak.Organization{
		Name:        "comp1",
		DisplayName: "公司1",
		Domains:     []string{"comp1.example.com"},
	}

	orgID, err := orgsService.Create(ctx, newOrg)
	if err != nil {
		slog.Error("创建组织失败: %v", err)
	} else {
		slog.Info("创建组织成功，ID: %s", orgID)

		// 将用户添加到组织
		if userID != "" {
			err = orgsService.AddMember(ctx, orgID, userID)
			if err != nil {
				slog.Error("将用户添加到组织失败: %v", err)
			} else {
				slog.Info("将用户添加到组织成功")
			}
		}
	}

	fmt.Println("Keycloak模块示例执行完成")
}
