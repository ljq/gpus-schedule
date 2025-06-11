// Package auth 提供用户认证和权限管理功能
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gpus-schedule/internal/config"

	"github.com/golang-jwt/jwt/v4"
)

var (
	// ErrInvalidCredentials 无效的凭证
	ErrInvalidCredentials = errors.New("无效的用户名或密码")
	// ErrTokenExpired 令牌已过期
	ErrTokenExpired = errors.New("令牌已过期")
	// ErrInvalidToken 无效的令牌
	ErrInvalidToken = errors.New("无效的令牌")
	// ErrPermissionDenied 权限不足
	ErrPermissionDenied = errors.New("权限不足")
	// ErrTenantNotFound 租户不存在
	ErrTenantNotFound = errors.New("租户不存在")
	// ErrUserNotFound 用户不存在
	ErrUserNotFound = errors.New("用户不存在")
)

// Role 用户角色
type Role string

const (
	// RoleAdmin 管理员角色
	RoleAdmin Role = "admin"
	// RoleUser 普通用户角色
	RoleUser Role = "user"
	// RoleGuest 访客角色
	RoleGuest Role = "guest"
)

// Permission 权限
type Permission string

const (
	// PermissionReadOnly 只读权限
	PermissionReadOnly Permission = "read_only"
	// PermissionReadWrite 读写权限
	PermissionReadWrite Permission = "read_write"
	// PermissionAdmin 管理员权限
	PermissionAdmin Permission = "admin"
)

// User 用户信息
type User struct {
	ID           string       `json:"id"`            // 用户ID
	Username     string       `json:"username"`      // 用户名
	PasswordHash string       `json:"password_hash"` // 密码哈希
	TenantID     string       `json:"tenant_id"`     // 所属租户ID
	Role         Role         `json:"role"`          // 用户角色
	Permissions  []Permission `json:"permissions"`   // 用户权限
	CreatedAt    time.Time    `json:"created_at"`    // 创建时间
	LastLogin    time.Time    `json:"last_login"`    // 最后登录时间
}

// Tenant 租户信息
type Tenant struct {
	ID          string    `json:"id"`          // 租户ID
	Name        string    `json:"name"`        // 租户名称
	Description string    `json:"description"` // 租户描述
	MaxGPUs     int       `json:"max_gpus"`    // 最大可用GPU数量
	MaxMemory   int64     `json:"max_memory"`  // 最大可用内存(MB)
	Priority    int       `json:"priority"`    // 优先级(1-100)
	CreatedAt   time.Time `json:"created_at"`  // 创建时间
	Active      bool      `json:"active"`      // 是否激活
}

// Claims JWT令牌声明
type Claims struct {
	jwt.RegisteredClaims
	UserID   string       `json:"user_id"`
	Username string       `json:"username"`
	TenantID string       `json:"tenant_id"`
	Role     Role         `json:"role"`
	Perms    []Permission `json:"permissions"`
}

// AuthManager 认证管理器
type AuthManager struct {
	users       map[string]*User   // 用户ID -> 用户信息
	usersByName map[string]*User   // 用户名 -> 用户信息
	tenants     map[string]*Tenant // 租户ID -> 租户信息
	jwtSecret   []byte             // JWT密钥
	tokenTTL    time.Duration      // 令牌有效期
	mutex       sync.RWMutex
	enabled     bool               // 是否启用认证
	config      *config.AuthConfig // 认证配置
}

// NewAuthManager 创建新的认证管理器
func NewAuthManager(cfg *config.Config) (*AuthManager, error) {
	// 如果认证未启用，返回空管理器
	if !cfg.Auth.Enabled {
		return &AuthManager{
			enabled: false,
		}, nil
	}
	// 如果未提供JWT密钥，则生成一个随机密钥
	secretBytes := []byte(cfg.Auth.JWTSecret)
	if len(secretBytes) == 0 {
		secretBytes = make([]byte, 32)
		_, err := rand.Read(secretBytes)
		if err != nil {
			return nil, fmt.Errorf("生成随机JWT密钥失败: %v", err)
		}
	}

	tokenTTL := time.Duration(cfg.Auth.TokenExpiry) * time.Hour

	// 创建认证管理器
	am := &AuthManager{
		users:       make(map[string]*User),
		usersByName: make(map[string]*User),
		tenants:     make(map[string]*Tenant),
		jwtSecret:   secretBytes,
		tokenTTL:    tokenTTL,
		enabled:     true,
		config:      &cfg.Auth,
	}

	// 初始化默认租户
	for tenantID, tenantCfg := range cfg.Tenants {
		tenant := &Tenant{
			ID:          tenantID,
			Name:        tenantID, // 使用租户ID作为名称
			Description: "默认租户描述",
			MaxGPUs:     tenantCfg.MaxGPUs,
			MaxMemory:   int64(tenantCfg.MaxMemoryPerGPU * tenantCfg.MaxGPUs),
			Priority:    tenantCfg.Priority,
			CreatedAt:   time.Now(),
			Active:      true,
		}
		am.tenants[tenant.ID] = tenant
	}

	// 初始化管理员用户
	for _, userCfg := range cfg.Users {
		if userCfg.Role != string(RoleAdmin) {
			continue
		}

		// 检查租户是否存在
		if _, exists := am.tenants[userCfg.TenantID]; !exists {
			return nil, fmt.Errorf("管理员用户的租户 %s 不存在", userCfg.TenantID)
		}

		// 创建管理员用户
		user := &User{
			ID:           generateID("user"),
			Username:     userCfg.Username,
			PasswordHash: hashPassword(userCfg.Password),
			TenantID:     userCfg.TenantID,
			Role:         RoleAdmin,
			Permissions:  []Permission{PermissionAdmin},
			CreatedAt:    time.Now(),
		}

		am.users[user.ID] = user
		am.usersByName[user.Username] = user
	}

	return am, nil
}

// IsEnabled 检查认证是否启用
func (am *AuthManager) IsEnabled() bool {
	return am.enabled
}

// RegisterTenant 注册租户
func (am *AuthManager) RegisterTenant(tenant *Tenant) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 生成租户ID（如果未提供）
	if tenant.ID == "" {
		tenant.ID = generateID("tenant")
	}

	// 设置创建时间
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now()
	}

	// 默认激活状态
	tenant.Active = true

	// 存储租户信息
	am.tenants[tenant.ID] = tenant

	return nil
}

// RegisterUser 注册用户
func (am *AuthManager) RegisterUser(user *User, password string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查租户是否存在
	if _, exists := am.tenants[user.TenantID]; !exists {
		return ErrTenantNotFound
	}

	// 检查用户名是否已存在
	if _, exists := am.usersByName[user.Username]; exists {
		return fmt.Errorf("用户名 %s 已存在", user.Username)
	}

	// 生成用户ID（如果未提供）
	if user.ID == "" {
		user.ID = generateID("user")
	}

	// 设置密码哈希
	user.PasswordHash = hashPassword(password)

	// 设置创建时间
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	// 存储用户信息
	am.users[user.ID] = user
	am.usersByName[user.Username] = user

	return nil
}

// Authenticate 用户认证
func (am *AuthManager) Authenticate(username, password string) (*User, error) {
	// 检查认证是否启用
	if !am.enabled {
		return nil, errors.New("认证未启用")
	}

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// 查找用户
	user, exists := am.usersByName[username]
	if !exists {
		return nil, ErrInvalidCredentials
	}

	// 验证密码
	if !verifyPassword(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	// 更新最后登录时间
	user.LastLogin = time.Now()

	return user, nil
}

// GenerateToken 生成JWT令牌
func (am *AuthManager) GenerateToken(user *User) (string, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// 创建令牌声明
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(am.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
		UserID:   user.ID,
		Username: user.Username,
		TenantID: user.TenantID,
		Role:     user.Role,
		Perms:    user.Permissions,
	}

	// 创建令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 签名令牌
	tokenString, err := token.SignedString(am.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("生成令牌失败: %v", err)
	}

	return tokenString, nil
}

// ValidateToken 验证JWT令牌
func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	// 检查认证是否启用
	if !am.enabled {
		return nil, errors.New("认证未启用")
	}

	// 如果允许访客访问，且令牌为空，返回访客声明
	if am.config.AllowGuest && tokenString == "" {
		return &Claims{
			UserID:   "guest",
			Username: "guest",
			Role:     RoleGuest,
			Perms:    []Permission{PermissionReadOnly},
		}, nil
	}

	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return am.jwtSecret, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, ErrTokenExpired
			}
		}
		return nil, ErrInvalidToken
	}

	// 提取声明
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// GetUserByID 根据ID获取用户
func (am *AuthManager) GetUserByID(userID string) (*User, error) {
	// 检查认证是否启用
	if !am.enabled {
		return nil, errors.New("认证未启用")
	}

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	user, exists := am.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetTenantByID 根据ID获取租户
func (am *AuthManager) GetTenantByID(tenantID string) (*Tenant, error) {
	// 检查认证是否启用
	if !am.enabled {
		return nil, errors.New("认证未启用")
	}

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	tenant, exists := am.tenants[tenantID]
	if !exists {
		return nil, ErrTenantNotFound
	}

	return tenant, nil
}

// GetAllTenants 获取所有租户
func (am *AuthManager) GetAllTenants() ([]*Tenant, error) {
	// 检查认证是否启用
	if !am.enabled {
		return nil, errors.New("认证未启用")
	}

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	tenants := make([]*Tenant, 0, len(am.tenants))
	for _, tenant := range am.tenants {
		tenants = append(tenants, tenant)
	}

	return tenants, nil
}

// HasPermission 检查用户是否有权限
func (am *AuthManager) HasPermission(userID string, permission Permission) (bool, error) {
	// 检查认证是否启用
	if !am.enabled {
		// 如果认证未启用，默认允许所有操作
		return true, nil
	}

	// 如果允许访客访问，默认允许所有操作
	if am.config != nil && am.config.AllowGuest {
		return true, nil
	}

	// 获取用户
	user, err := am.GetUserByID(userID)
	if err != nil {
		return false, err
	}

	// 管理员拥有所有权限
	if user.Role == RoleAdmin {
		return true, nil
	}

	// 检查用户权限
	for _, p := range user.Permissions {
		if p == permission {
			return true, nil
		}
	}

	return false, nil
}

// AllowGuestAccess 检查是否允许访客访问
func (am *AuthManager) AllowGuestAccess() bool {
	if !am.enabled {
		return true
	}

	return am.config != nil && am.config.AllowGuest
}

// GetAllUsers 获取所有用户
func (am *AuthManager) GetAllUsers() ([]*User, error) {
	// 检查认证是否启用
	if !am.enabled {
		return nil, errors.New("认证未启用")
	}

	am.mutex.RLock()
	defer am.mutex.RUnlock()

	users := make([]*User, 0, len(am.users))
	for _, user := range am.users {
		// 创建用户副本，不返回密码哈希
		userCopy := *user
		userCopy.PasswordHash = ""
		users = append(users, &userCopy)
	}

	return users, nil
}

// GetUsersByTenant 获取租户下的所有用户
func (am *AuthManager) GetUsersByTenant(tenantID string) ([]*User, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// 检查租户是否存在
	if _, exists := am.tenants[tenantID]; !exists {
		return nil, ErrTenantNotFound
	}

	users := make([]*User, 0)
	for _, user := range am.users {
		if user.TenantID == tenantID {
			users = append(users, user)
		}
	}

	return users, nil
}

// UpdateUser 更新用户信息
func (am *AuthManager) UpdateUser(user *User) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查用户是否存在
	oldUser, exists := am.users[user.ID]
	if !exists {
		return ErrUserNotFound
	}

	// 如果用户名发生变化，需要更新usersByName映射
	if oldUser.Username != user.Username {
		// 检查新用户名是否已存在
		if _, exists := am.usersByName[user.Username]; exists {
			return fmt.Errorf("用户名 %s 已存在", user.Username)
		}

		// 删除旧映射
		delete(am.usersByName, oldUser.Username)

		// 添加新映射
		am.usersByName[user.Username] = user
	}

	// 保留原始密码哈希（如果未提供新密码）
	if user.PasswordHash == "" {
		user.PasswordHash = oldUser.PasswordHash
	}

	// 更新用户信息
	am.users[user.ID] = user

	return nil
}

// UpdateTenant 更新租户信息
func (am *AuthManager) UpdateTenant(tenant *Tenant) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查租户是否存在
	if _, exists := am.tenants[tenant.ID]; !exists {
		return ErrTenantNotFound
	}

	// 更新租户信息
	am.tenants[tenant.ID] = tenant

	return nil
}

// DeleteUser 删除用户
func (am *AuthManager) DeleteUser(userID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查用户是否存在
	user, exists := am.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// 删除用户
	delete(am.users, userID)
	delete(am.usersByName, user.Username)

	return nil
}

// DeleteTenant 删除租户
func (am *AuthManager) DeleteTenant(tenantID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查租户是否存在
	if _, exists := am.tenants[tenantID]; !exists {
		return ErrTenantNotFound
	}

	// 检查是否有用户属于该租户
	for _, user := range am.users {
		if user.TenantID == tenantID {
			return fmt.Errorf("无法删除租户，存在关联用户")
		}
	}

	// 删除租户
	delete(am.tenants, tenantID)

	return nil
}

// ChangePassword 修改用户密码
func (am *AuthManager) ChangePassword(userID, oldPassword, newPassword string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查用户是否存在
	user, exists := am.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// 验证旧密码
	if !verifyPassword(oldPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// 设置新密码
	user.PasswordHash = hashPassword(newPassword)

	return nil
}

// ResetPassword 重置用户密码（管理员操作）
func (am *AuthManager) ResetPassword(userID, newPassword string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 检查用户是否存在
	user, exists := am.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// 设置新密码
	user.PasswordHash = hashPassword(newPassword)

	return nil
}

// CheckPermission 检查用户是否具有指定权限
func (am *AuthManager) CheckPermission(userID string, requiredPerm Permission) (bool, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// 检查用户是否存在
	user, exists := am.users[userID]
	if !exists {
		return false, ErrUserNotFound
	}

	// 管理员角色拥有所有权限
	if user.Role == RoleAdmin {
		return true, nil
	}

	// 检查用户权限
	for _, perm := range user.Permissions {
		if perm == requiredPerm || perm == PermissionAdmin {
			return true, nil
		}
	}

	return false, nil
}

// AuthMiddleware 认证中间件
func (am *AuthManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 从请求头中获取令牌
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "未提供认证令牌", http.StatusUnauthorized)
			return
		}

		// 提取令牌
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "认证格式无效", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]

		// 验证令牌
		claims, err := am.ValidateToken(tokenString)
		if err != nil {
			if err == ErrTokenExpired {
				http.Error(w, "认证令牌已过期", http.StatusUnauthorized)
			} else {
				http.Error(w, "认证令牌无效", http.StatusUnauthorized)
			}
			return
		}

		// 将用户信息添加到请求上下文
		r = r.WithContext(NewContextWithClaims(r.Context(), claims))

		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}

// PermissionMiddleware 权限中间件
func (am *AuthManager) PermissionMiddleware(requiredPerm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从请求上下文中获取令牌声明
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "未认证", http.StatusUnauthorized)
				return
			}

			// 管理员角色拥有所有权限
			if claims.Role == RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}

			// 检查用户权限
			hasPermission := false
			for _, perm := range claims.Perms {
				if perm == requiredPerm || perm == PermissionAdmin {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				http.Error(w, "权限不足", http.StatusForbidden)
				return
			}

			// 调用下一个处理器
			next.ServeHTTP(w, r)
		})
	}
}

// TenantMiddleware 租户中间件（确保用户只能访问自己租户的资源）
func (am *AuthManager) TenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 从请求上下文中获取令牌声明
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}

		// 从URL中提取租户ID
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			// 如果URL中没有租户ID，则尝试从请求体中获取
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				// 这里需要根据实际情况解析请求体
				// 为简化示例，这里假设已经从请求体中获取了租户ID
				// tenantID = extractTenantIDFromBody(r)
			}
		}

		// 如果找到了租户ID，则验证用户是否有权限访问该租户
		if tenantID != "" && tenantID != claims.TenantID {
			// 管理员可以访问所有租户
			if claims.Role != RoleAdmin {
				http.Error(w, "无权访问其他租户的资源", http.StatusForbidden)
				return
			}
		}

		// 调用下一个处理器
		next.ServeHTTP(w, r)
	})
}

// 辅助函数

// generateID 生成唯一ID
func generateID(prefix string) string {
	// 生成随机字节
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(fmt.Errorf("生成随机ID失败: %v", err))
	}

	// 转换为Base64字符串
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// 添加前缀和时间戳
	timestamp := time.Now().UnixNano() / 1000000 // 毫秒级时间戳
	return fmt.Sprintf("%s-%d-%s", prefix, timestamp, randomString[:8])
}

// hashPassword 哈希密码
func hashPassword(password string) string {
	// 在实际应用中，应该使用bcrypt等安全的哈希算法
	// 这里为了简化示例，使用Base64编码
	return base64.StdEncoding.EncodeToString([]byte(password))
}

// verifyPassword 验证密码
func verifyPassword(password, hash string) bool {
	// 在实际应用中，应该使用bcrypt等安全的哈希算法
	// 这里为了简化示例，使用Base64编码
	decodedBytes, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}
	return string(decodedBytes) == password
}
