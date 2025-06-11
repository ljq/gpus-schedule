// 主程序入口，启动GPU算力调度系统
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gpus-schedule/internal/auth"
	"gpus-schedule/internal/config"
	"gpus-schedule/internal/gpu"
	"gpus-schedule/internal/monitor"
	"gpus-schedule/internal/scheduler"
	"gpus-schedule/pkg/api"
)

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "configs/scheduler.yaml", "配置文件路径")
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	log.Printf("配置加载成功，主机: %s, 端口: %d", cfg.System.Host, cfg.System.Port)

	// 初始化GPU设备管理器
	deviceManager, err := gpu.NewDeviceManager(cfg.GPU.Devices, cfg.GPU.CheckInterval)
	if err != nil {
		log.Fatalf("初始化GPU设备管理器失败: %v", err)
	}

	// GPU设备已在初始化时发现

	devices := deviceManager.GetAllDeviceInfo()
	log.Printf("发现 %d 个GPU设备", len(devices))
	for _, device := range devices {
		log.Printf("设备 #%d: %s, 显存: %d MB", device.ID, device.Name, device.TotalMemory)
	}

	// 启动设备监控
	deviceManager.StartMonitoring()
	log.Println("设备监控已启动")

	// 初始化资源管理器
	resourceManager := gpu.NewResourceManager(deviceManager)

	// 初始化调度器
	schedulerInstance := scheduler.NewScheduler(
		cfg,
		resourceManager,
	)

	// 启动调度器
	schedulerInstance.Start()

	// 初始化认证管理器
	authManager, err := auth.NewAuthManager(cfg)
	if err != nil {
		log.Fatalf("初始化认证管理器失败: %v", err)
	}

	// 输出认证状态
	if authManager.IsEnabled() {
		log.Printf("认证系统已启用，JWT密钥长度: %d", len(cfg.Auth.JWTSecret))
		log.Printf("令牌有效期: %d 小时", cfg.Auth.TokenExpiry)
		log.Printf("用户存储类型: %s", cfg.Auth.UserStoreType)
		if cfg.Auth.AllowGuest {
			log.Printf("允许访客访问")
		}
	} else {
		log.Printf("认证系统未启用，所有API接口可自由访问")
	}

	// 初始化API服务器
	apiServer := api.NewAPIServer(
		schedulerInstance,
		cfg.System.Host,
		cfg.System.Port,
		authManager,
		cfg.Auth.Enabled,
	)

	// 初始化监控系统
	monitorSystem := monitor.NewMonitor(
		deviceManager,
		cfg.System.Host,
		cfg.Monitor.HTTPPort,
		time.Duration(cfg.Monitor.Interval)*time.Second,
		cfg.Monitor.Retention,
	)

	// 启动API服务器（非阻塞）
	go func() {
		log.Printf("API服务器启动在 %s:%d", cfg.System.Host, cfg.System.Port)
		if err := apiServer.Start(); err != nil {
			log.Fatalf("API服务器启动失败: %v", err)
		}
	}()

	// 启动监控系统（非阻塞）
	go func() {
		log.Printf("监控系统启动在 %s:%d", cfg.System.Host, cfg.Monitor.HTTPPort)
		if err := monitorSystem.Start(); err != nil {
			log.Fatalf("监控系统启动失败: %v", err)
		}
	}()

	// 启动资源过期清理（非阻塞）
	resourceManager.StartCleanupTask(time.Duration(cfg.Scheduler.Interval) * time.Second)

	// 启动超时任务检查（非阻塞）
	schedulerInstance.StartTimeoutChecker()

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 打印系统就绪信息
	log.Printf("GPU算力调度系统已就绪")
	log.Printf("API接口: http://%s:%d/api/", cfg.System.Host, cfg.System.Port)
	log.Printf("监控界面: http://%s:%d/", cfg.System.Host, cfg.Monitor.HTTPPort)

	// 等待退出信号
	sig := <-sigCh
	log.Printf("接收到信号 %v，开始优雅关闭", sig)

	// 优雅关闭
	shutdownGracefully(apiServer, monitorSystem, schedulerInstance)
}

// 优雅关闭所有组件
func shutdownGracefully(apiServer *api.APIServer, monitorSystem *monitor.Monitor, schedulerInstance *scheduler.Scheduler) {
	// 设置关闭超时
	timeout := 5 * time.Second
	deadline := time.Now().Add(timeout)

	// 关闭API服务器
	log.Printf("正在关闭API服务器...")
	if err := apiServer.Stop(); err != nil {
		log.Printf("关闭API服务器出错: %v", err)
	}

	// 关闭监控系统
	log.Printf("正在关闭监控系统...")
	if err := monitorSystem.Stop(); err != nil {
		log.Printf("关闭监控系统出错: %v", err)
	}

	// 关闭调度器
	log.Printf("正在关闭调度器...")
	schedulerInstance.Stop()

	// 检查是否超时
	if time.Now().After(deadline) {
		log.Printf("关闭超时，强制退出")
		os.Exit(1)
	}

	log.Printf("系统已安全关闭")
}