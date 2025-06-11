// Package auth 提供用户认证和权限管理功能
package auth

import (
	"context"
)

// 定义上下文键类型，避免与其他包的上下文键冲突
type contextKey string

// 定义上下文键常量
const (
	// claimsContextKey 用于在上下文中存储JWT声明
	claimsContextKey contextKey = "auth_claims"
	// userContextKey 用于在上下文中存储用户信息
	userContextKey contextKey = "auth_user"
	// tenantContextKey 用于在上下文中存储租户信息
	tenantContextKey contextKey = "auth_tenant"
)

// NewContextWithClaims 创建包含JWT声明的上下文
func NewContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext 从上下文中获取JWT声明
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}

// NewContextWithUser 创建包含用户信息的上下文
func NewContextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext 从上下文中获取用户信息
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey).(*User)
	return user, ok
}

// NewContextWithTenant 创建包含租户信息的上下文
func NewContextWithTenant(ctx context.Context, tenant *Tenant) context.Context {
	return context.WithValue(ctx, tenantContextKey, tenant)
}

// TenantFromContext 从上下文中获取租户信息
func TenantFromContext(ctx context.Context) (*Tenant, bool) {
	tenant, ok := ctx.Value(tenantContextKey).(*Tenant)
	return tenant, ok
}

// GetUserIDFromContext 从上下文中获取用户ID
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	// 首先尝试从Claims中获取
	if claims, ok := ClaimsFromContext(ctx); ok {
		return claims.UserID, true
	}

	// 然后尝试从User中获取
	if user, ok := UserFromContext(ctx); ok {
		return user.ID, true
	}

	return "", false
}

// GetTenantIDFromContext 从上下文中获取租户ID
func GetTenantIDFromContext(ctx context.Context) (string, bool) {
	// 首先尝试从Claims中获取
	if claims, ok := ClaimsFromContext(ctx); ok {
		return claims.TenantID, true
	}

	// 然后尝试从User中获取
	if user, ok := UserFromContext(ctx); ok {
		return user.TenantID, true
	}

	// 最后尝试从Tenant中获取
	if tenant, ok := TenantFromContext(ctx); ok {
		return tenant.ID, true
	}

	return "", false
}

// GetUserRoleFromContext 从上下文中获取用户角色
func GetUserRoleFromContext(ctx context.Context) (Role, bool) {
	// 首先尝试从Claims中获取
	if claims, ok := ClaimsFromContext(ctx); ok {
		return claims.Role, true
	}

	// 然后尝试从User中获取
	if user, ok := UserFromContext(ctx); ok {
		return user.Role, true
	}

	return "", false
}

// HasPermissionFromContext 检查上下文中的用户是否具有指定权限
func HasPermissionFromContext(ctx context.Context, requiredPerm Permission) bool {
	// 首先尝试从Claims中获取
	if claims, ok := ClaimsFromContext(ctx); ok {
		// 管理员角色拥有所有权限
		if claims.Role == RoleAdmin {
			return true
		}

		// 检查用户权限
		for _, perm := range claims.Perms {
			if perm == requiredPerm || perm == PermissionAdmin {
				return true
			}
		}
	}

	// 然后尝试从User中获取
	if user, ok := UserFromContext(ctx); ok {
		// 管理员角色拥有所有权限
		if user.Role == RoleAdmin {
			return true
		}

		// 检查用户权限
		for _, perm := range user.Permissions {
			if perm == requiredPerm || perm == PermissionAdmin {
				return true
			}
		}
	}

	return false
}
