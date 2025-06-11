package gpu

import (
	"fmt"
	"sync"
	"time"
)

// ResourceAllocation 表示资源分配信息
type ResourceAllocation struct {
	DeviceID    int       // 设备ID
	TenantID    string    // 租户ID
	TaskID      string    // 任务ID
	MemoryMB    int64     // 分配的内存(MB)
	ComputeUnit float64   // 分配的计算单元(百分比)
	AllocatedAt time.Time // 分配时间
	ExpiresAt   time.Time // 过期时间，零值表示永不过期
}

// ResourceManager GPU资源管理器
type ResourceManager struct {
	deviceManager *DeviceManager
	allocations   map[string][]*ResourceAllocation // 按租户ID索引的资源分配
	mutex         sync.RWMutex
}

// NewResourceManager 创建新的资源管理器
func NewResourceManager(deviceManager *DeviceManager) *ResourceManager {
	return &ResourceManager{
		deviceManager: deviceManager,
		allocations:   make(map[string][]*ResourceAllocation),
	}
}

// AllocateResource 分配GPU资源
func (rm *ResourceManager) AllocateResource(tenantID, taskID string, deviceID int, memoryMB int64, computeUnit float64, durationSeconds int) (*ResourceAllocation, error) {
	// 获取设备信息
	device, err := rm.deviceManager.GetDeviceInfo(deviceID)
	if err != nil {
		return nil, err
	}

	// 检查设备是否已分配给其他租户
	if device.AssignedTenant != "" && device.AssignedTenant != tenantID {
		return nil, fmt.Errorf("设备 %d 已分配给租户 %s", deviceID, device.AssignedTenant)
	}

	// 检查内存是否足够
	if memoryMB > 0 && memoryMB > device.FreeMemory {
		return nil, fmt.Errorf("设备 %d 可用内存不足: 请求 %d MB, 可用 %d MB", deviceID, memoryMB, device.FreeMemory)
	}

	// 创建资源分配
	allocation := &ResourceAllocation{
		DeviceID:    deviceID,
		TenantID:    tenantID,
		TaskID:      taskID,
		MemoryMB:    memoryMB,
		ComputeUnit: computeUnit,
		AllocatedAt: time.Now(),
	}

	// 设置过期时间（如果有）
	if durationSeconds > 0 {
		allocation.ExpiresAt = allocation.AllocatedAt.Add(time.Duration(durationSeconds) * time.Second)
	}

	// 分配设备给租户
	err = rm.deviceManager.AssignDeviceToTenant(deviceID, tenantID)
	if err != nil {
		return nil, err
	}

	// 记录分配
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.allocations[tenantID]; !exists {
		rm.allocations[tenantID] = make([]*ResourceAllocation, 0)
	}

	rm.allocations[tenantID] = append(rm.allocations[tenantID], allocation)

	return allocation, nil
}

// ReleaseResource 释放GPU资源
func (rm *ResourceManager) ReleaseResource(tenantID, taskID string, deviceID int) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// 查找分配记录
	allocations, exists := rm.allocations[tenantID]
	if !exists {
		return fmt.Errorf("租户 %s 没有资源分配", tenantID)
	}

	found := false
	newAllocations := make([]*ResourceAllocation, 0, len(allocations))

	for _, allocation := range allocations {
		if allocation.DeviceID == deviceID && allocation.TaskID == taskID {
			// 找到要释放的分配
			found = true

			// 释放设备
			err := rm.deviceManager.ReleaseDevice(deviceID, tenantID)
			if err != nil {
				return err
			}
		} else {
			// 保留其他分配
			newAllocations = append(newAllocations, allocation)
		}
	}

	if !found {
		return fmt.Errorf("未找到租户 %s 任务 %s 在设备 %d 上的资源分配", tenantID, taskID, deviceID)
	}

	// 更新分配列表
	if len(newAllocations) == 0 {
		delete(rm.allocations, tenantID)
	} else {
		rm.allocations[tenantID] = newAllocations
	}

	return nil
}

// GetTenantAllocations 获取租户的所有资源分配
func (rm *ResourceManager) GetTenantAllocations(tenantID string) []*ResourceAllocation {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	allocations, exists := rm.allocations[tenantID]
	if !exists {
		return []*ResourceAllocation{}
	}

	// 返回副本以避免并发修改
	result := make([]*ResourceAllocation, len(allocations))
	copy(result, allocations)

	return result
}

// GetAllAllocations 获取所有资源分配
func (rm *ResourceManager) GetAllAllocations() map[string][]*ResourceAllocation {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	// 返回副本以避免并发修改
	result := make(map[string][]*ResourceAllocation)
	for tenantID, allocations := range rm.allocations {
		result[tenantID] = make([]*ResourceAllocation, len(allocations))
		copy(result[tenantID], allocations)
	}

	return result
}

// CleanupExpiredAllocations 清理过期的资源分配
func (rm *ResourceManager) CleanupExpiredAllocations() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	now := time.Now()

	for tenantID, allocations := range rm.allocations {
		newAllocations := make([]*ResourceAllocation, 0, len(allocations))

		for _, allocation := range allocations {
			// 检查是否过期
			if !allocation.ExpiresAt.IsZero() && now.After(allocation.ExpiresAt) {
				// 释放设备
				_ = rm.deviceManager.ReleaseDevice(allocation.DeviceID, tenantID)
			} else {
				// 保留未过期的分配
				newAllocations = append(newAllocations, allocation)
			}
		}

		// 更新分配列表
		if len(newAllocations) == 0 {
			delete(rm.allocations, tenantID)
		} else {
			rm.allocations[tenantID] = newAllocations
		}
	}
}

// StartCleanupTask 启动定期清理任务
func (rm *ResourceManager) StartCleanupTask(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			<-ticker.C
			rm.CleanupExpiredAllocations()
		}
	}()
}

// GetDeviceUtilization 获取设备利用率信息
func (rm *ResourceManager) GetDeviceUtilization() map[int]float64 {
	devices := rm.deviceManager.GetAllDeviceInfo()
	utilization := make(map[int]float64)

	for _, device := range devices {
		utilization[device.ID] = device.Utilization
	}

	return utilization
}

// GetDeviceMemoryUsage 获取设备内存使用情况
func (rm *ResourceManager) GetDeviceMemoryUsage() map[int]struct {
	Total int64
	Used  int64
	Free  int64
} {
	devices := rm.deviceManager.GetAllDeviceInfo()
	memoryUsage := make(map[int]struct {
		Total int64
		Used  int64
		Free  int64
	})

	for _, device := range devices {
		memoryUsage[device.ID] = struct {
			Total int64
			Used  int64
			Free  int64
		}{
			Total: device.TotalMemory,
			Used:  device.UsedMemory,
			Free:  device.FreeMemory,
		}
	}

	return memoryUsage
}

// GetAvailableDevices 获取可用的设备列表
func (rm *ResourceManager) GetAvailableDevices() []*DeviceInfo {
	return rm.deviceManager.GetAvailableDevices()
}
