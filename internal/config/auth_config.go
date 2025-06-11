// Package config 提供配置文件的读取和解析功能
package config

// AuthConfig 认证系统配置
type AuthConfig struct {
	Enabled       bool   `yaml:"enabled"`         // 是否启用认证
	JWTSecret     string `yaml:"jwt_secret"`      // JWT密钥
	TokenExpiry   int    `yaml:"token_expiry"`    // 令牌过期时间(小时)
	AllowGuest    bool   `yaml:"allow_guest"`     // 是否允许访客访问
	AdminUser     string `yaml:"admin_user"`      // 管理员用户名
	AdminPass     string `yaml:"admin_pass"`      // 管理员密码
	UserStoreType string `yaml:"user_store_type"` // 用户存储类型(memory/file)
	UserStoreFile string `yaml:"user_store_file"` // 用户存储文件路径
}

// UserConfig 用户配置
type UserConfig struct {
	Username    string   `yaml:"username"`    // 用户名
	Password    string   `yaml:"password"`    // 密码
	TenantID    string   `yaml:"tenant_id"`   // 所属租户ID
	Role        string   `yaml:"role"`        // 用户角色
	Permissions []string `yaml:"permissions"` // 用户权限
}

// 更新Config结构体，添加Auth字段
func init() {
	// 这里不需要实际代码，只是为了文档说明
	// Config结构体将在update_config.go中更新
}

// GetDefaultAuthConfig 返回默认认证配置
func GetDefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Enabled:       true,
		JWTSecret:     "", // 空字符串表示自动生成随机密钥
		TokenExpiry:   24,
		AllowGuest:    false,
		AdminUser:     "admin",
		AdminPass:     "admin123", // 默认密码，应在生产环境中修改
		UserStoreType: "memory",
		UserStoreFile: "users.json",
	}
}

// GetDefaultUserConfig 返回默认用户配置
func GetDefaultUserConfig() UserConfig {
	return UserConfig{
		Username:    "",
		Password:    "",
		TenantID:    "default",
		Role:        "user",
		Permissions: []string{"read_only"},
	}
}
