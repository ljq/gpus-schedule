// Package api 提供GPU算力调度系统的API接口
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"gpus-schedule/internal/auth"
)

// AuthMiddleware 认证中间件
type AuthMiddleware struct {
	authManager *auth.AuthManager
	enabled     bool
}

// NewAuthMiddleware 创建新的认证中间件
func NewAuthMiddleware(authManager *auth.AuthManager, enabled bool) *AuthMiddleware {
	return &AuthMiddleware{
		authManager: authManager,
		enabled:     enabled,
	}
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"` // 用户名
	Password string `json:"password"` // 密码
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token     string `json:"token"`      // JWT令牌
	UserID    string `json:"user_id"`    // 用户ID
	Username  string `json:"username"`   // 用户名
	TenantID  string `json:"tenant_id"`  // 租户ID
	Role      string `json:"role"`       // 角色
	ExpiresAt int64  `json:"expires_at"` // 过期时间戳
}

// UserResponse 用户信息响应
type UserResponse struct {
	ID          string   `json:"id"`          // 用户ID
	Username    string   `json:"username"`    // 用户名
	TenantID    string   `json:"tenant_id"`   // 租户ID
	Role        string   `json:"role"`        // 角色
	Permissions []string `json:"permissions"` // 权限
	CreatedAt   string   `json:"created_at"`  // 创建时间
	LastLogin   string   `json:"last_login"`  // 最后登录时间
}

// TenantResponse 租户信息响应
type TenantResponse struct {
	ID          string `json:"id"`          // 租户ID
	Name        string `json:"name"`        // 租户名称
	Description string `json:"description"` // 租户描述
	MaxGPUs     int    `json:"max_gpus"`    // 最大可用GPU数量
	MaxMemory   int64  `json:"max_memory"`  // 最大可用内存(MB)
	Priority    int    `json:"priority"`    // 优先级
	CreatedAt   string `json:"created_at"`  // 创建时间
	Active      bool   `json:"active"`      // 是否激活
}

// 使用 api.go 中定义的 ErrorResponse

// Authenticate 认证中间件函数
func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 如果认证未启用，直接放行
		if !am.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// 跳过登录路径的认证
		if r.URL.Path == "/api/login" {
			next.ServeHTTP(w, r)
			return
		}

		// 从请求头中获取令牌
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// 如果允许访客访问，创建访客上下文
			if am.authManager.AllowGuestAccess() {
				ctx := auth.NewContextWithClaims(r.Context(), &auth.Claims{
					UserID:   "guest",
					Username: "guest",
					Role:     auth.RoleGuest,
					TenantID: "",
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "未提供认证令牌"})
			return
		}

		// 提取令牌
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "认证格式无效"})
			return
		}
		tokenString := parts[1]

		// 验证令牌
		claims, err := am.authManager.ValidateToken(tokenString)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			var errMsg string
			if err == auth.ErrTokenExpired {
				errMsg = "认证令牌已过期"
			} else {
				errMsg = "认证令牌无效"
			}
			json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg})
			return
		}

		// 将用户信息添加到请求上下文
		ctx := auth.NewContextWithClaims(r.Context(), claims)
		r = r.WithContext(ctx)

		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}

// RequireRole 要求特定角色的中间件
func (am *AuthMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 如果认证未启用，直接放行
			if !am.enabled {
				next.ServeHTTP(w, r)
				return
			}

			// 从请求上下文中获取令牌声明
			claims, ok := auth.ClaimsFromContext(r.Context())
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "未认证"})
				return
			}

			// 检查用户角色
			if claims.Role != auth.Role(role) && claims.Role != auth.RoleAdmin {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "权限不足"})
				return
			}

			// 调用下一个处理器
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission 要求特定权限的中间件
func (am *AuthMiddleware) RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 如果认证未启用，直接放行
			if !am.enabled {
				next.ServeHTTP(w, r)
				return
			}

			// 从请求上下文中获取令牌声明
			claims, ok := auth.ClaimsFromContext(r.Context())
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "未认证"})
				return
			}

			// 管理员角色拥有所有权限
			if claims.Role == auth.RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}

			// 检查用户权限
			hasPermission := false
			for _, p := range claims.Perms {
				if p == auth.Permission(perm) || p == auth.PermissionAdmin {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "权限不足"})
				return
			}

			// 调用下一个处理器
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenantAccess 要求租户访问权限的中间件
func (am *AuthMiddleware) RequireTenantAccess() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 如果认证未启用，直接放行
			if !am.enabled {
				next.ServeHTTP(w, r)
				return
			}

			// 从请求上下文中获取令牌声明
			claims, ok := auth.ClaimsFromContext(r.Context())
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "未认证"})
				return
			}

			// 从URL中提取租户ID
			tenantID := r.URL.Query().Get("tenant_id")
			if tenantID == "" {
				// 如果URL中没有租户ID，则尝试从路径中获取
				pathParts := strings.Split(r.URL.Path, "/")
				if len(pathParts) >= 3 && pathParts[1] == "api" && pathParts[2] == "tenants" && len(pathParts) >= 4 {
					tenantID = pathParts[3]
				}
			}

			// 如果找到了租户ID，则验证用户是否有权限访问该租户
			if tenantID != "" && tenantID != claims.TenantID {
				// 管理员可以访问所有租户
				if claims.Role != "admin" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(ErrorResponse{Error: "无权访问其他租户的资源"})
					return
				}
			}

			// 调用下一个处理器
			next.ServeHTTP(w, r)
		})
	}
}

// HandleLogin 处理登录请求
func (am *AuthMiddleware) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// 检查认证是否启用
	if !am.enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "认证未启用"})
		return
	}

	// 只接受POST方法
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "方法不允许"})
		return
	}

	// 解析请求体
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "无效的请求格式"})
		return
	}

	// 验证用户凭证
	user, err := am.authManager.Authenticate(req.Username, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "用户名或密码错误"})
		return
	}

	// 生成令牌
	token, err := am.authManager.GenerateToken(user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "生成令牌失败"})
		return
	}

	// 设置过期时间（默认24小时）
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	// 返回令牌和用户信息
	resp := LoginResponse{
		Token:     token,
		UserID:    user.ID,
		Username:  user.Username,
		TenantID:  user.TenantID,
		Role:      string(user.Role),
		ExpiresAt: expiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleGetCurrentUser 处理获取当前用户信息请求
func (am *AuthMiddleware) HandleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// 检查认证是否启用
	if !am.enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "认证未启用"})
		return
	}

	// 从上下文中获取声明
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "未认证"})
		return
	}

	// 如果是访客用户，返回访客信息
	if claims.UserID == "guest" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(UserResponse{
			ID:          "guest",
			Username:    "guest",
			TenantID:    "",
			Role:        "guest",
			Permissions: []string{"read_only"},
			CreatedAt:   "",
			LastLogin:   "",
		})
		return
	}

	// 获取用户信息
	user, err := am.authManager.GetUserByID(claims.UserID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "获取用户信息失败"})
		return
	}

	// 返回用户信息
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(UserResponse{
		ID:          user.ID,
		Username:    user.Username,
		TenantID:    user.TenantID,
		Role:        string(user.Role),
		Permissions: convertPermissions(user.Permissions),
		CreatedAt:   user.CreatedAt.Format(time.RFC3339),
		LastLogin:   user.LastLogin.Format(time.RFC3339),
	})
}

// HandleGetTenantInfo 获取租户信息
func (am *AuthMiddleware) HandleGetTenantInfo(w http.ResponseWriter, r *http.Request) {
	// 检查认证是否启用
	if !am.enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "认证未启用"})
		return
	}

	// 从请求上下文中获取令牌声明
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "未认证"})
		return
	}

	// 从URL中提取租户ID
	tenantID := r.URL.Path[len("/api/tenants/"):]
	if tenantID == "" {
		// 如果未指定租户ID，则使用当前用户的租户ID
		tenantID = claims.TenantID
	} else if tenantID != claims.TenantID && claims.Role != "admin" {
		// 非管理员用户只能查看自己的租户信息
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "无权访问其他租户的信息"})
		return
	}

	// 获取租户信息
	tenant, err := am.authManager.GetTenantByID(tenantID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "租户不存在"})
		return
	}

	// 返回租户信息
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TenantResponse{
		ID:          tenant.ID,
		Name:        tenant.Name,
		Description: tenant.Description,
		MaxGPUs:     tenant.MaxGPUs,
		MaxMemory:   tenant.MaxMemory,
		Priority:    tenant.Priority,
		CreatedAt:   tenant.CreatedAt.Format(time.RFC3339),
		Active:      tenant.Active,
	})
}

// HandleGetTenants 处理获取所有租户信息请求
func (am *AuthMiddleware) HandleGetTenants(w http.ResponseWriter, r *http.Request) {
	// 检查认证是否启用
	if !am.enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "认证未启用"})
		return
	}

	// 从上下文中获取声明
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "未认证"})
		return
	}

	// 检查是否为管理员
	if claims.Role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "权限不足"})
		return
	}

	// 获取所有租户
	tenants, err := am.authManager.GetAllTenants()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "获取租户信息失败"})
		return
	}

	// 转换为响应格式
	responses := make([]TenantResponse, 0, len(tenants))
	for _, tenant := range tenants {
		responses = append(responses, TenantResponse{
			ID:          tenant.ID,
			Name:        tenant.Name,
			Description: tenant.Description,
			MaxGPUs:     tenant.MaxGPUs,
			MaxMemory:   tenant.MaxMemory,
			Priority:    tenant.Priority,
			CreatedAt:   tenant.CreatedAt.Format(time.RFC3339),
			Active:      tenant.Active,
		})
	}

	// 返回租户信息
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responses)
}

// 辅助函数

// convertPermissions 将权限类型转换为字符串切片
func convertPermissions(perms []auth.Permission) []string {
	result := make([]string, len(perms))
	for i, p := range perms {
		result[i] = string(p)
	}
	return result
}
