// Package gpu 提供GPU设备管理和资源分配功能
package gpu

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DeviceInfo 表示单个GPU设备的信息
type DeviceInfo struct {
	ID             int       // 设备ID
	Name           string    // 设备名称
	TotalMemory    int64     // 总内存(MB)
	UsedMemory     int64     // 已使用内存(MB)
	FreeMemory     int64     // 可用内存(MB)
	Utilization    float64   // GPU利用率(%)
	Temperature    int       // 温度(°C)
	PowerUsage     float64   // 功耗(W)
	PowerLimit     float64   // 功耗限制(W)
	AssignedTenant string    // 分配给的租户
	LastUpdated    time.Time // 最后更新时间
}

// DeviceManager GPU设备管理器
type DeviceManager struct {
	devices        map[int]*DeviceInfo // 设备信息映射表
	deviceIDs      []int               // 可用设备ID列表
	mutex          sync.RWMutex        // 读写锁
	updateInterval time.Duration       // 更新间隔
}

// NewDeviceManager 创建新的设备管理器
func NewDeviceManager(deviceIDs []int, updateIntervalSeconds int) (*DeviceManager, error) {
	manager := &DeviceManager{
		devices:        make(map[int]*DeviceInfo),
		updateInterval: time.Duration(updateIntervalSeconds) * time.Second,
	}

	// 如果未指定设备ID，则自动发现所有设备
	if len(deviceIDs) == 0 {
		ids, err := discoverGPUDevices()
		if err != nil {
			return nil, err
		}
		manager.deviceIDs = ids
	} else {
		manager.deviceIDs = deviceIDs
	}

	// 初始化设备信息
	for _, id := range manager.deviceIDs {
		manager.devices[id] = &DeviceInfo{
			ID:          id,
			LastUpdated: time.Now(),
		}
	}

	// 首次更新设备信息
	err := manager.UpdateDeviceInfo()
	if err != nil {
		return nil, fmt.Errorf("初始化设备信息失败: %v", err)
	}

	return manager, nil
}

// discoverGPUDevices 自动发现系统中的GPU设备
func discoverGPUDevices() ([]int, error) {
	// 使用nvidia-smi命令获取设备列表
	cmd := exec.Command("nvidia-smi", "--query-gpu=index", "--format=csv,noheader")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行nvidia-smi命令失败: %v", err)
	}

	// 解析设备ID
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	deviceIDs := make([]int, 0, len(lines))

	for _, line := range lines {
		id, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		deviceIDs = append(deviceIDs, id)
	}

	if len(deviceIDs) == 0 {
		return nil, fmt.Errorf("未发现GPU设备")
	}

	return deviceIDs, nil
}

// UpdateDeviceInfo 更新所有设备的信息
func (dm *DeviceManager) UpdateDeviceInfo() error {
	// 使用nvidia-smi命令获取设备详细信息
	cmd := exec.Command(
		"nvidia-smi",
		"--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu,power.draw,power.limit",
		"--format=csv,noheader,nounits",
	)

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("执行nvidia-smi命令失败: %v", err)
	}

	// 解析输出
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	for _, line := range lines {
		fields := strings.Split(line, ", ")
		if len(fields) < 9 {
			continue
		}

		// 解析设备ID
		id, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}

		// 检查是否是我们管理的设备
		device, exists := dm.devices[id]
		if !exists {
			continue
		}

		// 更新设备信息
		device.Name = strings.TrimSpace(fields[1])
		device.TotalMemory, _ = strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64)
		device.UsedMemory, _ = strconv.ParseInt(strings.TrimSpace(fields[3]), 10, 64)
		device.FreeMemory, _ = strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64)
		device.Utilization, _ = strconv.ParseFloat(strings.TrimSpace(fields[5]), 64)
		device.Temperature, _ = strconv.Atoi(strings.TrimSpace(fields[6]))
		device.PowerUsage, _ = strconv.ParseFloat(strings.TrimSpace(fields[7]), 64)
		device.PowerLimit, _ = strconv.ParseFloat(strings.TrimSpace(fields[8]), 64)
		device.LastUpdated = time.Now()
	}

	return nil
}

// StartMonitoring 开始定期监控设备状态
func (dm *DeviceManager) StartMonitoring() {
	go func() {
		ticker := time.NewTicker(dm.updateInterval)
		defer ticker.Stop()

		for {
			<-ticker.C
			err := dm.UpdateDeviceInfo()
			if err != nil {
				fmt.Printf("更新设备信息失败: %v\n", err)
			}
		}
	}()
}

// GetDeviceInfo 获取指定设备的信息
func (dm *DeviceManager) GetDeviceInfo(deviceID int) (*DeviceInfo, error) {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	device, exists := dm.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("设备ID %d 不存在", deviceID)
	}

	return device, nil
}

// GetAllDeviceInfo 获取所有设备的信息
func (dm *DeviceManager) GetAllDeviceInfo() []*DeviceInfo {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	devices := make([]*DeviceInfo, 0, len(dm.devices))
	for _, device := range dm.devices {
		devices = append(devices, device)
	}

	return devices
}

// GetAvailableDevices 获取可用的设备列表
func (dm *DeviceManager) GetAvailableDevices() []*DeviceInfo {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	availableDevices := make([]*DeviceInfo, 0)
	for _, device := range dm.devices {
		if device.AssignedTenant == "" {
			availableDevices = append(availableDevices, device)
		}
	}

	return availableDevices
}

// AssignDeviceToTenant 将设备分配给租户
func (dm *DeviceManager) AssignDeviceToTenant(deviceID int, tenantID string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	device, exists := dm.devices[deviceID]
	if !exists {
		return fmt.Errorf("设备ID %d 不存在", deviceID)
	}

	if device.AssignedTenant != "" && device.AssignedTenant != tenantID {
		return fmt.Errorf("设备ID %d 已分配给租户 %s", deviceID, device.AssignedTenant)
	}

	device.AssignedTenant = tenantID
	return nil
}

// ReleaseDevice 释放设备
func (dm *DeviceManager) ReleaseDevice(deviceID int, tenantID string) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	device, exists := dm.devices[deviceID]
	if !exists {
		return fmt.Errorf("设备ID %d 不存在", deviceID)
	}

	if device.AssignedTenant != tenantID {
		return fmt.Errorf("设备ID %d 未分配给租户 %s", deviceID, tenantID)
	}

	device.AssignedTenant = ""
	return nil
}

// GetDeviceCount 获取设备总数
func (dm *DeviceManager) GetDeviceCount() int {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	return len(dm.devices)
}

// GetDevicesByTenant 获取分配给指定租户的设备
func (dm *DeviceManager) GetDevicesByTenant(tenantID string) []*DeviceInfo {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	devices := make([]*DeviceInfo, 0)
	for _, device := range dm.devices {
		if device.AssignedTenant == tenantID {
			devices = append(devices, device)
		}
	}

	return devices
}
