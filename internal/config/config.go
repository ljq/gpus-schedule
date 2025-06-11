// Package config 提供配置文件的读取和解析功能
package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

// SystemConfig 系统配置
type SystemConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	LogLevel string `yaml:"log_level"`
	LogFile  string `yaml:"log_file"`
}

// GPUConfig GPU资源配置
type GPUConfig struct {
	Enabled           bool    `yaml:"enabled"`
	Devices           []int   `yaml:"devices"`
	MaxMemoryPercent  float64 `yaml:"max_memory_percent"`
	MaxComputePercent float64 `yaml:"max_compute_percent"`
	CheckInterval     int     `yaml:"check_interval"`
}

// SchedulerConfig 调度策略配置
type SchedulerConfig struct {
	Algorithm   string `yaml:"algorithm"`
	QueueSize   int    `yaml:"queue_size"`
	Interval    int    `yaml:"interval"`
	TaskTimeout int    `yaml:"task_timeout"`
	Preemptive  bool   `yaml:"preemptive"`
}

// TenantConfig 租户配置
type TenantConfig struct {
	MaxGPUs         int `yaml:"max_gpus"`
	MaxMemoryPerGPU int `yaml:"max_memory_per_gpu"`
	Priority        int `yaml:"priority"`
}

// MonitorConfig 监控系统配置
type MonitorConfig struct {
	Enabled   bool `yaml:"enabled"`
	Interval  int  `yaml:"interval"`
	Retention int  `yaml:"retention"`
	HTTPAPI   bool `yaml:"http_api"`
	HTTPPort  int  `yaml:"http_port"`
}

// Config 总配置结构
type Config struct {
	System    SystemConfig            `yaml:"system"`
	GPU       GPUConfig               `yaml:"gpu"`
	Scheduler SchedulerConfig         `yaml:"scheduler"`
	Tenants   map[string]TenantConfig `yaml:"tenants"`
	Monitor   MonitorConfig           `yaml:"monitor"`
	Auth      AuthConfig              `yaml:"auth"`
	Users     []UserConfig            `yaml:"users"`
}

// LoadConfig 从文件加载配置
func LoadConfig(filePath string) (*Config, error) {
	config := &Config{}

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", filePath)
	}

	// 读取配置文件
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证配置
	err = validateConfig(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// validateConfig 验证配置是否有效
func validateConfig(config *Config) error {
	// 验证系统配置
	if config.System.Port <= 0 || config.System.Port > 65535 {
		return fmt.Errorf("无效的端口号: %d", config.System.Port)
	}

	// 验证GPU配置
	if config.GPU.Enabled {
		if config.GPU.MaxMemoryPercent < 0 || config.GPU.MaxMemoryPercent > 100 {
			return fmt.Errorf("无效的GPU内存使用百分比: %.2f", config.GPU.MaxMemoryPercent)
		}
		if config.GPU.MaxComputePercent < 0 || config.GPU.MaxComputePercent > 100 {
			return fmt.Errorf("无效的GPU计算负载百分比: %.2f", config.GPU.MaxComputePercent)
		}
	}

	// 验证调度器配置
	validAlgorithms := map[string]bool{
		"round_robin": true,
		"least_used":  true,
		"priority":    true,
	}
	if !validAlgorithms[config.Scheduler.Algorithm] {
		return fmt.Errorf("无效的调度算法: %s", config.Scheduler.Algorithm)
	}

	// 验证租户配置
	for name, tenant := range config.Tenants {
		if tenant.Priority < 1 || tenant.Priority > 100 {
			return fmt.Errorf("租户 %s 的优先级无效: %d (应在1-100之间)", name, tenant.Priority)
		}
	}

	// 验证监控配置
	if config.Monitor.Enabled && config.Monitor.HTTPAPI {
		if config.Monitor.HTTPPort <= 0 || config.Monitor.HTTPPort > 65535 {
			return fmt.Errorf("无效的监控HTTP端口号: %d", config.Monitor.HTTPPort)
		}
	}

	// 验证认证配置
	if config.Auth.Enabled {
		if config.Auth.TokenExpiry <= 0 {
			return fmt.Errorf("无效的令牌过期时间: %d", config.Auth.TokenExpiry)
		}

		validUserStoreTypes := map[string]bool{
			"memory": true,
			"file":   true,
		}
		if !validUserStoreTypes[config.Auth.UserStoreType] {
			return fmt.Errorf("无效的用户存储类型: %s", config.Auth.UserStoreType)
		}

		if config.Auth.UserStoreType == "file" && config.Auth.UserStoreFile == "" {
			return fmt.Errorf("用户存储类型为file时，必须指定用户存储文件路径")
		}

		// 验证是否至少有一个管理员用户
		hasAdmin := false
		for _, user := range config.Users {
			if user.Role == "admin" {
				hasAdmin = true
				break
			}
		}

		if !hasAdmin {
			return fmt.Errorf("必须至少配置一个管理员用户")
		}
	}

	return nil
}

// GetDefaultConfig 返回默认配置
func GetDefaultConfig() *Config {
	return &Config{
		System: SystemConfig{
			Host:     "0.0.0.0",
			Port:     8080,
			LogLevel: "info",
			LogFile:  "",
		},
		GPU: GPUConfig{
			Enabled:           true,
			Devices:           []int{},
			MaxMemoryPercent:  95,
			MaxComputePercent: 95,
			CheckInterval:     5,
		},
		Scheduler: SchedulerConfig{
			Algorithm:   "least_used",
			QueueSize:   100,
			Interval:    500,
			TaskTimeout: 3600,
			Preemptive:  false,
		},
		Tenants: map[string]TenantConfig{
			"default": {
				MaxGPUs:         1,
				MaxMemoryPerGPU: 0,
				Priority:        50,
			},
		},
		Monitor: MonitorConfig{
			Enabled:   true,
			Interval:  10,
			Retention: 24,
			HTTPAPI:   true,
			HTTPPort:  8081,
		},
		Auth: GetDefaultAuthConfig(),
		Users: []UserConfig{
			{
				Username:    "admin",
				Password:    "admin123",
				TenantID:    "default",
				Role:        "admin",
				Permissions: []string{"admin"},
			},
		},
	}
}
