// 用户管理模块，实现用户认证和权限管理
package auth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// 系统角色常量
const (
	RoleSystem Role = "system" // 系统角色
)

// 用户权限
const (
	PermissionViewTasks      = "view_tasks"       // 查看任务
	PermissionCreateTasks    = "create_tasks"     // 创建任务
	PermissionCancelTasks    = "cancel_tasks"     // 取消任务
	PermissionManageUsers    = "manage_users"     // 管理用户
	PermissionManageTenants  = "manage_tenants"   // 管理租户
	PermissionViewAllTasks   = "view_all_tasks"   // 查看所有任务
	PermissionCancelAllTasks = "cancel_all_tasks" // 取消所有任务
	PermissionViewStatistics = "view_statistics"  // 查看统计信息
	PermissionManageSystem   = "manage_system"    // 管理系统
)

// 默认角色权限映射
var defaultRolePermissions = map[Role][]string{
	RoleAdmin: {
		PermissionViewTasks,
		PermissionCreateTasks,
		PermissionCancelTasks,
		PermissionManageUsers,
		PermissionManageTenants,
		PermissionViewAllTasks,
		PermissionCancelAllTasks,
		PermissionViewStatistics,
		PermissionManageSystem,
	},
	RoleUser: {
		PermissionViewTasks,
		PermissionCreateTasks,
		PermissionCancelTasks,
		PermissionViewStatistics,
	},
	RoleGuest: {
		PermissionViewTasks,
		PermissionViewStatistics,
	},
	RoleSystem: {
		PermissionViewAllTasks,
		PermissionCancelAllTasks,
		PermissionManageSystem,
	},
}

// UserInfo 表示系统用户信息（用于存储和序列化）
type UserInfo struct {
	ID           string   `yaml:"id"`            // 用户ID
	Username     string   `yaml:"username"`      // 用户名
	PasswordHash string   `yaml:"password_hash"` // 密码哈希
	Role         string   `yaml:"role"`          // 角色
	TenantID     string   `yaml:"tenant_id"`     // 租户ID
	Email        string   `yaml:"email"`         // 邮箱
	CreatedAt    string   `yaml:"created_at"`    // 创建时间
	LastLogin    string   `yaml:"last_login"`    // 最后登录时间
	Permissions  []string `yaml:"permissions"`   // 额外权限
}

// UserStore 用户存储接口
type UserStore interface {
	// 获取所有用户
	GetAllUsers() ([]UserInfo, error)
	// 根据ID获取用户
	GetUserByID(id string) (*UserInfo, error)
	// 根据用户名获取用户
	GetUserByUsername(username string) (*UserInfo, error)
	// 创建用户
	CreateUser(user UserInfo) error
	// 更新用户
	UpdateUser(user UserInfo) error
	// 删除用户
	DeleteUser(id string) error
	// 验证用户凭证
	ValidateCredentials(username, password string) (*UserInfo, error)
}

// JWTClaims 表示JWT令牌中的声明
type JWTClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	Permissions []string `json:"permissions"`
}

// MemoryUserStore 内存用户存储
type MemoryUserStore struct {
	users map[string]UserInfo
	mutex sync.RWMutex
}

// NewMemoryUserStore 创建内存用户存储
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users: make(map[string]UserInfo),
	}
}

// GetAllUsers 获取所有用户
func (s *MemoryUserStore) GetAllUsers() ([]UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	users := make([]UserInfo, 0, len(s.users))
	for _, user := range s.users {
		// 不返回密码哈希
		userCopy := user
		userCopy.PasswordHash = ""
		users = append(users, userCopy)
	}
	return users, nil
}

// GetUserByID 根据ID获取用户
func (s *MemoryUserStore) GetUserByID(id string) (*UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, errors.New("用户不存在")
	}

	// 不返回密码哈希
	userCopy := user
	userCopy.PasswordHash = ""
	return &userCopy, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *MemoryUserStore) GetUserByUsername(username string) (*UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			// 不返回密码哈希
			userCopy := user
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, errors.New("用户不存在")
}

// CreateUser 创建用户
func (s *MemoryUserStore) CreateUser(user UserInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查用户名是否已存在
	for _, existingUser := range s.users {
		if existingUser.Username == user.Username {
			return errors.New("用户名已存在")
		}
	}

	// 设置创建时间
	if user.CreatedAt == "" {
		user.CreatedAt = time.Now().Format(time.RFC3339)
	}

	s.users[user.ID] = user
	return nil
}

// UpdateUser 更新用户
func (s *MemoryUserStore) UpdateUser(user UserInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查用户是否存在
	_, ok := s.users[user.ID]
	if !ok {
		return errors.New("用户不存在")
	}

	// 检查用户名是否与其他用户冲突
	for id, existingUser := range s.users {
		if id != user.ID && existingUser.Username == user.Username {
			return errors.New("用户名已被其他用户使用")
		}
	}

	s.users[user.ID] = user
	return nil
}

// DeleteUser 删除用户
func (s *MemoryUserStore) DeleteUser(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查用户是否存在
	_, ok := s.users[id]
	if !ok {
		return errors.New("用户不存在")
	}

	delete(s.users, id)
	return nil
}

// ValidateCredentials 验证用户凭证
func (s *MemoryUserStore) ValidateCredentials(username, password string) (*UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			// 验证密码
			err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
			if err != nil {
				return nil, errors.New("密码错误")
			}

			// 不返回密码哈希
			userCopy := user
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, errors.New("用户不存在")
}

// FileUserStore 文件用户存储
type FileUserStore struct {
	filePath string
	users    map[string]UserInfo
	mutex    sync.RWMutex
}

// NewFileUserStore 创建文件用户存储
func NewFileUserStore(filePath string) (*FileUserStore, error) {
	store := &FileUserStore{
		filePath: filePath,
		users:    make(map[string]UserInfo),
	}

	// 加载用户数据
	if err := store.loadUsers(); err != nil {
		// 如果文件不存在，创建空文件
		if os.IsNotExist(err) {
			return store, store.saveUsers()
		}
		return nil, err
	}

	return store, nil
}

// loadUsers 从文件加载用户数据
func (s *FileUserStore) loadUsers() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	users := make(map[string]UserInfo)
	if err := yaml.Unmarshal(data, &users); err != nil {
		return err
	}

	s.users = users
	return nil
}

// saveUsers 保存用户数据到文件
func (s *FileUserStore) saveUsers() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data, err := yaml.Marshal(s.users)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(s.filePath, data, 0644)
}

// GetAllUsers 获取所有用户
func (s *FileUserStore) GetAllUsers() ([]UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	users := make([]UserInfo, 0, len(s.users))
	for _, user := range s.users {
		// 不返回密码哈希
		userCopy := user
		userCopy.PasswordHash = ""
		users = append(users, userCopy)
	}
	return users, nil
}

// GetUserByID 根据ID获取用户
func (s *FileUserStore) GetUserByID(id string) (*UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, errors.New("用户不存在")
	}

	// 不返回密码哈希
	userCopy := user
	userCopy.PasswordHash = ""
	return &userCopy, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *FileUserStore) GetUserByUsername(username string) (*UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			// 不返回密码哈希
			userCopy := user
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, errors.New("用户不存在")
}

// CreateUser 创建用户
func (s *FileUserStore) CreateUser(user UserInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查用户名是否已存在
	for _, existingUser := range s.users {
		if existingUser.Username == user.Username {
			return errors.New("用户名已存在")
		}
	}

	// 设置创建时间
	if user.CreatedAt == "" {
		user.CreatedAt = time.Now().Format(time.RFC3339)
	}

	s.users[user.ID] = user

	// 保存到文件
	return s.saveUsers()
}

// UpdateUser 更新用户
func (s *FileUserStore) UpdateUser(user UserInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查用户是否存在
	_, ok := s.users[user.ID]
	if !ok {
		return errors.New("用户不存在")
	}

	// 检查用户名是否与其他用户冲突
	for id, existingUser := range s.users {
		if id != user.ID && existingUser.Username == user.Username {
			return errors.New("用户名已被其他用户使用")
		}
	}

	s.users[user.ID] = user

	// 保存到文件
	return s.saveUsers()
}

// DeleteUser 删除用户
func (s *FileUserStore) DeleteUser(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查用户是否存在
	_, ok := s.users[id]
	if !ok {
		return errors.New("用户不存在")
	}

	delete(s.users, id)

	// 保存到文件
	return s.saveUsers()
}

// ValidateCredentials 验证用户凭证
func (s *FileUserStore) ValidateCredentials(username, password string) (*UserInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			// 验证密码
			err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
			if err != nil {
				return nil, errors.New("密码错误")
			}

			// 不返回密码哈希
			userCopy := user
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}

	return nil, errors.New("用户不存在")
}

// UserManager 用户管理器
type UserManager struct {
	store       UserStore
	jwtSecret   []byte
	tokenExpiry time.Duration
}

// NewUserManager 创建用户管理器
func NewUserManager(store UserStore, jwtSecret string, tokenExpiry time.Duration) *UserManager {
	return &UserManager{
		store:       store,
		jwtSecret:   []byte(jwtSecret),
		tokenExpiry: tokenExpiry,
	}
}

// CreateUser 创建用户
func (m *UserManager) CreateUser(id, username, password, role, tenantID, email string) (*UserInfo, error) {
	// 生成密码哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("生成密码哈希失败: %v", err)
	}

	// 创建用户
	user := UserInfo{
		ID:           id,
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         role,
		TenantID:     tenantID,
		Email:        email,
		CreatedAt:    time.Now().Format(time.RFC3339),
		Permissions:  []string{},
	}

	// 保存用户
	if err := m.store.CreateUser(user); err != nil {
		return nil, err
	}

	// 不返回密码哈希
	user.PasswordHash = ""
	return &user, nil
}

// Authenticate 用户认证
func (m *UserManager) Authenticate(username, password string) (string, *UserInfo, error) {
	// 验证用户凭证
	user, err := m.store.ValidateCredentials(username, password)
	if err != nil {
		return "", nil, err
	}

	// 更新最后登录时间
	userWithHash, err := m.store.GetUserByID(user.ID)
	if err != nil {
		return "", nil, err
	}

	userWithHash.LastLogin = time.Now().Format(time.RFC3339)
	if updateErr := m.store.UpdateUser(*userWithHash); updateErr != nil {
		return "", nil, err
	}

	// 生成JWT令牌
	token, err := m.generateToken(user)
	if err != nil {
		return "", nil, err
	}

	return token, user, nil
}

// VerifyToken 验证令牌
func (m *UserManager) VerifyToken(tokenString string) (*JWTClaims, error) {
	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}

		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	// 验证令牌有效性
	if !token.Valid {
		return nil, errors.New("无效的令牌")
	}

	// 获取声明
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("无效的令牌声明")
	}

	return claims, nil
}

// GetUserByID 根据ID获取用户
func (m *UserManager) GetUserByID(id string) (*UserInfo, error) {
	return m.store.GetUserByID(id)
}

// GetAllUsers 获取所有用户
func (m *UserManager) GetAllUsers() ([]UserInfo, error) {
	return m.store.GetAllUsers()
}

// UpdateUser 更新用户
func (m *UserManager) UpdateUser(user UserInfo) error {
	// 获取原始用户以保留密码哈希
	originalUser, err := m.store.GetUserByID(user.ID)
	if err != nil {
		return err
	}

	// 保留原始密码哈希
	user.PasswordHash = originalUser.PasswordHash

	return m.store.UpdateUser(user)
}

// ChangePassword 修改密码
func (m *UserManager) ChangePassword(id, oldPassword, newPassword string) error {
	// 获取用户
	user, err := m.store.GetUserByID(id)
	if err != nil {
		return err
	}

	// 验证旧密码
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		return errors.New("旧密码错误")
	}

	// 生成新密码哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("生成密码哈希失败: %v", err)
	}

	// 更新密码
	user.PasswordHash = string(hashedPassword)
	return m.store.UpdateUser(*user)
}

// DeleteUser 删除用户
func (m *UserManager) DeleteUser(id string) error {
	return m.store.DeleteUser(id)
}

// HasPermission 检查用户是否有权限
func (m *UserManager) HasPermission(userID, permission string) (bool, error) {
	// 获取用户
	user, err := m.store.GetUserByID(userID)
	if err != nil {
		return false, err
	}

	// 检查用户自定义权限
	for _, p := range user.Permissions {
		if p == permission {
			return true, nil
		}
	}

	// 检查角色默认权限
	permissions, ok := defaultRolePermissions[Role(user.Role)]
	if !ok {
		return false, nil
	}

	for _, p := range permissions {
		if p == permission {
			return true, nil
		}
	}

	return false, nil
}

// generateToken 生成JWT令牌
func (m *UserManager) generateToken(user *UserInfo) (string, error) {
	// 创建声明
	claims := JWTClaims{
		UserID:      user.ID,
		Username:    user.Username,
		Role:        user.Role,
		TenantID:    user.TenantID,
		Email:       user.Email,
		Permissions: user.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// 创建令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 签名令牌
	tokenString, err := token.SignedString(m.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// InitAdminUser 初始化管理员用户
func (m *UserManager) InitAdminUser(adminUsers []UserInfo) error {
	for _, adminUser := range adminUsers {
		// 检查用户是否已存在
		existingUser, err := m.store.GetUserByUsername(adminUser.Username)
		if err == nil && existingUser != nil {
			// 用户已存在，跳过
			continue
		}

		// 创建管理员用户
		if err := m.store.CreateUser(adminUser); err != nil {
			return fmt.Errorf("创建管理员用户失败: %v", err)
		}
	}

	return nil
}
