// Package monitor 提供GPU资源监控功能
package monitor

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"gpus-schedule/internal/gpu"
)

// Monitor GPU监控系统
type Monitor struct {
	deviceManager *gpu.DeviceManager
	server        *http.Server
	metrics       map[int]*DeviceMetrics  // 设备ID -> 设备指标
	history       map[int][]DeviceMetrics // 设备ID -> 历史指标
	historyLimit  int                     // 历史记录限制
	mutex         sync.RWMutex
	collectTicker *time.Ticker
	stopCh        chan struct{}
}

// DeviceMetrics 设备指标
type DeviceMetrics struct {
	DeviceID       int       `json:"device_id"`       // 设备ID
	Timestamp      time.Time `json:"timestamp"`       // 时间戳
	GPUUtilization int       `json:"gpu_utilization"` // GPU利用率(%)
	MemoryUsed     int64     `json:"memory_used"`     // 已用显存(MB)
	MemoryTotal    int64     `json:"memory_total"`    // 总显存(MB)
	Temperature    int       `json:"temperature"`     // 温度(°C)
	PowerUsage     float64   `json:"power_usage"`     // 功耗(W)
	PowerLimit     float64   `json:"power_limit"`     // 功耗限制(W)
	FanSpeed       int       `json:"fan_speed"`       // 风扇转速(%)
	Allocated      bool      `json:"allocated"`       // 是否已分配
	TenantID       string    `json:"tenant_id"`       // 租户ID(如果已分配)
	TaskID         string    `json:"task_id"`         // 任务ID(如果已分配)
}

// SystemMetrics 系统指标
type SystemMetrics struct {
	Timestamp         time.Time          `json:"timestamp"`          // 时间戳
	TotalGPUs         int                `json:"total_gpus"`         // 总GPU数量
	AllocatedGPUs     int                `json:"allocated_gpus"`     // 已分配GPU数量
	AvgUtilization    float64            `json:"avg_utilization"`    // 平均利用率
	AvgMemoryUsage    float64            `json:"avg_memory_usage"`   // 平均内存使用率
	AvgTemperature    float64            `json:"avg_temperature"`    // 平均温度
	AvgPowerUsage     float64            `json:"avg_power_usage"`    // 平均功耗
	DeviceMetrics     []DeviceMetrics    `json:"device_metrics"`     // 各设备指标
	ActiveTenants     int                `json:"active_tenants"`     // 活跃租户数
	ActiveTasks       int                `json:"active_tasks"`       // 活跃任务数
	TenantUtilization map[string]float64 `json:"tenant_utilization"` // 租户利用率
}

// NewMonitor 创建新的监控系统
func NewMonitor(deviceManager *gpu.DeviceManager, host string, port int, collectInterval time.Duration, historyLimit int) *Monitor {
	monitor := &Monitor{
		deviceManager: deviceManager,
		server: &http.Server{
			Addr: fmt.Sprintf("%s:%d", host, port),
		},
		metrics:      make(map[int]*DeviceMetrics),
		history:      make(map[int][]DeviceMetrics),
		historyLimit: historyLimit,
		stopCh:       make(chan struct{}),
	}

	// 设置路由
	mux := http.NewServeMux()
	mux.HandleFunc("/api/monitor/metrics", monitor.handleMetrics)
	mux.HandleFunc("/api/monitor/device/", monitor.handleDeviceMetrics)
	mux.HandleFunc("/api/monitor/history", monitor.handleHistory)
	mux.HandleFunc("/api/monitor/history/", monitor.handleDeviceHistory)

	// 设置静态文件服务
	fs := http.FileServer(http.Dir("./web/static"))
	mux.Handle("/", fs)

	monitor.server.Handler = mux
	monitor.collectTicker = time.NewTicker(collectInterval)

	return monitor
}

// Start 启动监控系统
func (m *Monitor) Start() error {
	// 启动指标收集
	go m.collectMetrics()

	// 启动HTTP服务器
	return m.server.ListenAndServe()
}

// Stop 停止监控系统
func (m *Monitor) Stop() error {
	// 停止指标收集
	m.collectTicker.Stop()
	close(m.stopCh)

	// 停止HTTP服务器
	return m.server.Close()
}

// collectMetrics 收集指标
func (m *Monitor) collectMetrics() {
	for {
		select {
		case <-m.collectTicker.C:
			m.updateMetrics()
		case <-m.stopCh:
			return
		}
	}
}

// updateMetrics 更新指标
func (m *Monitor) updateMetrics() {
	// 获取所有设备信息
	devices := m.deviceManager.GetAllDeviceInfo()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 更新每个设备的指标
	for _, device := range devices {
		// 创建新的指标
		metrics := &DeviceMetrics{
			DeviceID:       device.ID,
			Timestamp:      time.Now(),
			GPUUtilization: int(device.Utilization),
			MemoryUsed:     device.UsedMemory,
			MemoryTotal:    device.TotalMemory,
			Temperature:    device.Temperature,
			PowerUsage:     device.PowerUsage,
			PowerLimit:     device.PowerLimit,
			FanSpeed:       0,                           // 设备信息中没有风扇转速
			Allocated:      device.AssignedTenant != "", // 根据是否分配给租户判断
			TenantID:       device.AssignedTenant,
			TaskID:         "", // 设备信息中没有任务ID
		}

		// 更新当前指标
		m.metrics[device.ID] = metrics

		// 添加到历史记录
		if _, ok := m.history[device.ID]; !ok {
			m.history[device.ID] = make([]DeviceMetrics, 0, m.historyLimit)
		}

		// 添加新指标到历史记录
		m.history[device.ID] = append(m.history[device.ID], *metrics)

		// 如果历史记录超过限制，删除最旧的记录
		if len(m.history[device.ID]) > m.historyLimit {
			m.history[device.ID] = m.history[device.ID][1:]
		}
	}
}

// GetSystemMetrics 获取系统指标
func (m *Monitor) GetSystemMetrics() SystemMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 获取所有设备信息
	devices := m.deviceManager.GetAllDeviceInfo()

	// 计算系统指标
	totalGPUs := len(devices)
	allocatedGPUs := 0
	totalUtilization := 0
	totalMemoryUsage := float64(0)
	totalTemperature := 0
	totalPowerUsage := float64(0)

	// 租户统计
	tenants := make(map[string]bool)
	tasks := make(map[string]bool)
	tenantUtilization := make(map[string]float64)
	tenantGPUCount := make(map[string]int)

	// 收集设备指标
	deviceMetrics := make([]DeviceMetrics, 0, totalGPUs)
	for _, device := range devices {
		if metrics, ok := m.metrics[device.ID]; ok {
			deviceMetrics = append(deviceMetrics, *metrics)

			// 更新统计信息
			if device.AssignedTenant != "" {
				allocatedGPUs++
				tenants[device.AssignedTenant] = true
				// 设备信息中没有任务ID，不更新tasks

				// 更新租户利用率
				tenantUtilization[device.AssignedTenant] += float64(metrics.GPUUtilization)
				tenantGPUCount[device.AssignedTenant]++
			}

			totalUtilization += metrics.GPUUtilization
			totalMemoryUsage += float64(metrics.MemoryUsed) / float64(metrics.MemoryTotal)
			totalTemperature += metrics.Temperature
			totalPowerUsage += metrics.PowerUsage
		}
	}

	// 计算平均值
	avgUtilization := float64(0)
	avgMemoryUsage := float64(0)
	avgTemperature := float64(0)
	avgPowerUsage := float64(0)

	if totalGPUs > 0 {
		avgUtilization = float64(totalUtilization) / float64(totalGPUs)
		avgMemoryUsage = totalMemoryUsage / float64(totalGPUs) * 100 // 转换为百分比
		avgTemperature = float64(totalTemperature) / float64(totalGPUs)
		avgPowerUsage = totalPowerUsage / float64(totalGPUs)
	}

	// 计算每个租户的平均利用率
	for tenant, total := range tenantUtilization {
		if count := tenantGPUCount[tenant]; count > 0 {
			tenantUtilization[tenant] = total / float64(count)
		}
	}

	return SystemMetrics{
		Timestamp:         time.Now(),
		TotalGPUs:         totalGPUs,
		AllocatedGPUs:     allocatedGPUs,
		AvgUtilization:    avgUtilization,
		AvgMemoryUsage:    avgMemoryUsage,
		AvgTemperature:    avgTemperature,
		AvgPowerUsage:     avgPowerUsage,
		DeviceMetrics:     deviceMetrics,
		ActiveTenants:     len(tenants),
		ActiveTasks:       len(tasks),
		TenantUtilization: tenantUtilization,
	}
}

// GetDeviceMetrics 获取设备指标
func (m *Monitor) GetDeviceMetrics(deviceID int) (*DeviceMetrics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	metrics, ok := m.metrics[deviceID]
	if !ok {
		return nil, fmt.Errorf("device %d not found", deviceID)
	}

	return metrics, nil
}

// GetDeviceHistory 获取设备历史指标
func (m *Monitor) GetDeviceHistory(deviceID int) ([]DeviceMetrics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	history, ok := m.history[deviceID]
	if !ok {
		return nil, fmt.Errorf("device %d not found", deviceID)
	}

	// 返回历史记录的副本
	result := make([]DeviceMetrics, len(history))
	copy(result, history)

	return result, nil
}

// handleMetrics 处理指标请求
func (m *Monitor) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取系统指标
	metrics := m.GetSystemMetrics()

	// 返回JSON响应
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		log.Printf("Error encoding metrics: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleDeviceMetrics 处理设备指标请求
func (m *Monitor) handleDeviceMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从URL中提取设备ID
	path := r.URL.Path
	deviceIDStr := path[len("/api/monitor/device/"):]
	var deviceID int
	if _, err := fmt.Sscanf(deviceIDStr, "%d", &deviceID); err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	// 获取设备指标
	metrics, err := m.GetDeviceMetrics(deviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// 返回JSON响应
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		log.Printf("Error encoding metrics: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleHistory 处理历史指标请求
func (m *Monitor) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取所有设备的历史指标
	m.mutex.RLock()
	history := make(map[int][]DeviceMetrics)
	for deviceID, deviceHistory := range m.history {
		history[deviceID] = make([]DeviceMetrics, len(deviceHistory))
		copy(history[deviceID], deviceHistory)
	}
	m.mutex.RUnlock()

	// 返回JSON响应
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(history); err != nil {
		log.Printf("Error encoding history: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleDeviceHistory 处理设备历史指标请求
func (m *Monitor) handleDeviceHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从URL中提取设备ID
	path := r.URL.Path
	deviceIDStr := path[len("/api/monitor/history/"):]
	var deviceID int
	if _, err := fmt.Sscanf(deviceIDStr, "%d", &deviceID); err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	// 获取设备历史指标
	history, err := m.GetDeviceHistory(deviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// 返回JSON响应
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(history); err != nil {
		log.Printf("Error encoding history: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
