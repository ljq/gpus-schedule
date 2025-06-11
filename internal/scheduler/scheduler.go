// Package scheduler 提供GPU资源调度功能
package scheduler

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"gpus-schedule/internal/config"
	"gpus-schedule/internal/gpu"
)

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"   // 等待中
	TaskRunning   TaskStatus = "running"   // 运行中
	TaskCompleted TaskStatus = "completed" // 已完成
	TaskFailed    TaskStatus = "failed"    // 失败
	TaskCancelled TaskStatus = "cancelled" // 已取消
)

// Task 表示一个GPU计算任务
type Task struct {
	ID          string     // 任务ID
	TenantID    string     // 租户ID
	Name        string     // 任务名称
	Description string     // 任务描述
	Status      TaskStatus // 任务状态
	GPURequest  int        // 请求的GPU数量
	MemoryMB    int64      // 请求的内存(MB)
	Priority    int        // 优先级(1-100)
	CreatedAt   time.Time  // 创建时间
	StartedAt   time.Time  // 开始时间
	FinishedAt  time.Time  // 完成时间
	DeviceIDs   []int      // 分配的设备ID
	Timeout     int        // 超时时间(秒)
	CreatedBy   string     // 创建者ID
}

// Scheduler GPU调度器
type Scheduler struct {
	config          *config.Config
	resourceManager *gpu.ResourceManager
	taskQueue       []*Task
	runningTasks    map[string]*Task
	tenantQuotas    map[string]struct {
		MaxGPUs         int
		MaxMemoryPerGPU int64
		UsedGPUs        int
	}
	mutex     sync.RWMutex
	isRunning bool
	stopChan  chan struct{}
}

// NewScheduler 创建新的调度器
func NewScheduler(cfg *config.Config, resourceManager *gpu.ResourceManager) *Scheduler {
	scheduler := &Scheduler{
		config:          cfg,
		resourceManager: resourceManager,
		taskQueue:       make([]*Task, 0),
		runningTasks:    make(map[string]*Task),
		tenantQuotas: make(map[string]struct {
			MaxGPUs         int
			MaxMemoryPerGPU int64
			UsedGPUs        int
		}),
		stopChan: make(chan struct{}),
	}

	// 初始化租户配额
	for tenantID, tenantConfig := range cfg.Tenants {
		scheduler.tenantQuotas[tenantID] = struct {
			MaxGPUs         int
			MaxMemoryPerGPU int64
			UsedGPUs        int
		}{
			MaxGPUs:         tenantConfig.MaxGPUs,
			MaxMemoryPerGPU: int64(tenantConfig.MaxMemoryPerGPU),
			UsedGPUs:        0,
		}
	}

	return scheduler
}

// Start 启动调度器
func (s *Scheduler) Start() {
	s.mutex.Lock()
	if s.isRunning {
		s.mutex.Unlock()
		return
	}
	s.isRunning = true
	s.mutex.Unlock()

	go s.scheduleLoop()
}

// Stop 停止调度器
func (s *Scheduler) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return
	}

	s.isRunning = false
	s.stopChan <- struct{}{}
}

// SubmitTask 提交任务
func (s *Scheduler) SubmitTask(task *Task) error {
	// 验证任务参数
	if task.TenantID == "" {
		return fmt.Errorf("租户ID不能为空")
	}

	// 检查租户是否存在
	s.mutex.RLock()
	quota, exists := s.tenantQuotas[task.TenantID]
	s.mutex.RUnlock()

	if !exists {
		// 如果租户不存在，使用默认配额
		defaultQuota, exists := s.tenantQuotas["default"]
		if !exists {
			return fmt.Errorf("租户 %s 不存在且未配置默认租户", task.TenantID)
		}
		quota = defaultQuota
	}

	// 检查请求的GPU数量是否超过配额
	if task.GPURequest > quota.MaxGPUs {
		return fmt.Errorf("请求的GPU数量 %d 超过租户 %s 的配额 %d", task.GPURequest, task.TenantID, quota.MaxGPUs)
	}

	// 设置任务状态和时间
	task.Status = TaskPending
	task.CreatedAt = time.Now()

	// 设置任务超时
	if task.Timeout <= 0 && s.config.Scheduler.TaskTimeout > 0 {
		task.Timeout = s.config.Scheduler.TaskTimeout
	}

	// 添加到任务队列
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查队列是否已满
	if len(s.taskQueue) >= s.config.Scheduler.QueueSize {
		return fmt.Errorf("任务队列已满")
	}

	s.taskQueue = append(s.taskQueue, task)

	return nil
}

// CancelTask 取消任务
func (s *Scheduler) CancelTask(taskID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 检查运行中的任务
	if task, exists := s.runningTasks[taskID]; exists {
		// 释放资源
		for _, deviceID := range task.DeviceIDs {
			_ = s.resourceManager.ReleaseResource(task.TenantID, taskID, deviceID)
		}

		// 更新租户配额使用情况
		quota := s.tenantQuotas[task.TenantID]
		quota.UsedGPUs -= len(task.DeviceIDs)
		s.tenantQuotas[task.TenantID] = quota

		// 更新任务状态
		task.Status = TaskCancelled
		task.FinishedAt = time.Now()

		// 从运行中任务列表移除
		delete(s.runningTasks, taskID)

		return nil
	}

	// 检查等待中的任务
	for i, task := range s.taskQueue {
		if task.ID == taskID {
			// 更新任务状态
			task.Status = TaskCancelled
			task.FinishedAt = time.Now()

			// 从队列中移除
			s.taskQueue = append(s.taskQueue[:i], s.taskQueue[i+1:]...)

			return nil
		}
	}

	return fmt.Errorf("任务 %s 不存在", taskID)
}

// GetTaskStatus 获取任务状态
func (s *Scheduler) GetTaskStatus(taskID string) (*Task, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// 检查运行中的任务
	if task, exists := s.runningTasks[taskID]; exists {
		return task, nil
	}

	// 检查等待中的任务
	for _, task := range s.taskQueue {
		if task.ID == taskID {
			return task, nil
		}
	}

	return nil, fmt.Errorf("任务 %s 不存在", taskID)
}

// GetTenantTasks 获取租户的所有任务
func (s *Scheduler) GetTenantTasks(tenantID string) []*Task {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tasks := make([]*Task, 0)

	// 检查运行中的任务
	for _, task := range s.runningTasks {
		if task.TenantID == tenantID {
			tasks = append(tasks, task)
		}
	}

	// 检查等待中的任务
	for _, task := range s.taskQueue {
		if task.TenantID == tenantID {
			tasks = append(tasks, task)
		}
	}

	return tasks
}

// scheduleLoop 调度循环
func (s *Scheduler) scheduleLoop() {
	ticker := time.NewTicker(time.Duration(s.config.Scheduler.Interval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.scheduleOnce()
		case <-s.stopChan:
			return
		}
	}
}

// scheduleOnce 执行一次调度
func (s *Scheduler) scheduleOnce() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 如果没有等待的任务，直接返回
	if len(s.taskQueue) == 0 {
		return
	}

	// 根据调度算法对任务排序
	s.sortTaskQueue()

	// 尝试为每个任务分配资源
	scheduledTasks := make([]*Task, 0)

	for i, task := range s.taskQueue {
		// 检查租户配额
		quota := s.tenantQuotas[task.TenantID]
		if quota.UsedGPUs+task.GPURequest > quota.MaxGPUs {
			// 超过配额，跳过此任务
			continue
		}

		// 尝试分配资源
		deviceIDs, err := s.allocateGPUs(task)
		if err != nil {
			// 资源不足，跳过此任务
			continue
		}

		// 资源分配成功，更新任务状态
		task.Status = TaskRunning
		task.StartedAt = time.Now()
		task.DeviceIDs = deviceIDs

		// 更新租户配额使用情况
		quota.UsedGPUs += len(deviceIDs)
		s.tenantQuotas[task.TenantID] = quota

		// 添加到运行中任务列表
		s.runningTasks[task.ID] = task

		// 标记为已调度
		scheduledTasks = append(scheduledTasks, task)

		// 从队列中移除
		s.taskQueue = append(s.taskQueue[:i-len(scheduledTasks)+1], s.taskQueue[i+1:]...)
	}
}

// sortTaskQueue 根据调度算法对任务队列排序
func (s *Scheduler) sortTaskQueue() {
	switch s.config.Scheduler.Algorithm {
	case "priority":
		// 按优先级排序（高到低）
		s.sortTaskQueueByPriority()
	case "round_robin":
		// 轮询调度，按租户ID和创建时间排序
		s.sortTaskQueueByRoundRobin()
	default:
		// 默认使用最少使用优先
		s.sortTaskQueueByLeastUsed()
	}
}

// sortTaskQueueByPriority 按优先级排序
func (s *Scheduler) sortTaskQueueByPriority() {
	// 按优先级（高到低）和创建时间（早到晚）排序
	sort.Slice(s.taskQueue, func(i, j int) bool {
		if s.taskQueue[i].Priority != s.taskQueue[j].Priority {
			return s.taskQueue[i].Priority > s.taskQueue[j].Priority
		}
		return s.taskQueue[i].CreatedAt.Before(s.taskQueue[j].CreatedAt)
	})
}

// sortTaskQueueByRoundRobin 按轮询方式排序
func (s *Scheduler) sortTaskQueueByRoundRobin() {
	// 按租户ID和创建时间排序，确保不同租户的任务交替执行
	sort.Slice(s.taskQueue, func(i, j int) bool {
		if s.taskQueue[i].TenantID != s.taskQueue[j].TenantID {
			return s.taskQueue[i].TenantID < s.taskQueue[j].TenantID
		}
		return s.taskQueue[i].CreatedAt.Before(s.taskQueue[j].CreatedAt)
	})
}

// sortTaskQueueByLeastUsed 按最少使用排序
func (s *Scheduler) sortTaskQueueByLeastUsed() {
	// 按租户已使用的GPU数量（少到多）和创建时间排序
	sort.Slice(s.taskQueue, func(i, j int) bool {
		usedGPUsI := s.tenantQuotas[s.taskQueue[i].TenantID].UsedGPUs
		usedGPUsJ := s.tenantQuotas[s.taskQueue[j].TenantID].UsedGPUs
		if usedGPUsI != usedGPUsJ {
			return usedGPUsI < usedGPUsJ
		}
		return s.taskQueue[i].CreatedAt.Before(s.taskQueue[j].CreatedAt)
	})
}

// allocateGPUs 为任务分配GPU资源
func (s *Scheduler) allocateGPUs(task *Task) ([]int, error) {
	// 获取可用设备
	availableDevices := s.resourceManager.GetAvailableDevices()
	if len(availableDevices) < task.GPURequest {
		return nil, fmt.Errorf("可用GPU数量不足: 请求 %d, 可用 %d", task.GPURequest, len(availableDevices))
	}

	// 分配设备
	allocatedDevices := make([]int, 0, task.GPURequest)
	for i := 0; i < task.GPURequest; i++ {
		deviceID := availableDevices[i].ID

		// 分配资源
		_, err := s.resourceManager.AllocateResource(
			task.TenantID,
			task.ID,
			deviceID,
			task.MemoryMB,
			100.0, // 默认分配100%的计算单元
			task.Timeout,
		)

		if err != nil {
			// 分配失败，释放已分配的资源
			for _, id := range allocatedDevices {
				_ = s.resourceManager.ReleaseResource(task.TenantID, task.ID, id)
			}
			return nil, fmt.Errorf("分配GPU资源失败: %v", err)
		}

		allocatedDevices = append(allocatedDevices, deviceID)
	}

	return allocatedDevices, nil
}

// CheckTimeoutTasks 检查并处理超时任务
func (s *Scheduler) CheckTimeoutTasks() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()

	for id, task := range s.runningTasks {
		// 检查是否超时
		if task.Timeout > 0 {
			timeoutTime := task.StartedAt.Add(time.Duration(task.Timeout) * time.Second)
			if now.After(timeoutTime) {
				// 任务超时，释放资源
				for _, deviceID := range task.DeviceIDs {
					_ = s.resourceManager.ReleaseResource(task.TenantID, task.ID, deviceID)
				}

				// 更新租户配额使用情况
				quota := s.tenantQuotas[task.TenantID]
				quota.UsedGPUs -= len(task.DeviceIDs)
				s.tenantQuotas[task.TenantID] = quota

				// 更新任务状态
				task.Status = TaskFailed
				task.FinishedAt = now

				// 从运行中任务列表移除
				delete(s.runningTasks, id)
			}
		}
	}
}

// StartTimeoutChecker 启动超时检查器
func (s *Scheduler) StartTimeoutChecker() {
	go func() {
		ticker := time.NewTicker(10 * time.Second) // 每10秒检查一次
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.CheckTimeoutTasks()
			case <-s.stopChan:
				return
			}
		}
	}()
}

// GetSchedulerStats 获取调度器统计信息
func (s *Scheduler) GetSchedulerStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := make(map[string]interface{})

	// 任务统计
	stats["pending_tasks"] = len(s.taskQueue)
	stats["running_tasks"] = len(s.runningTasks)

	// 租户统计
	tenantStats := make(map[string]map[string]interface{})
	for tenantID, quota := range s.tenantQuotas {
		tenantStats[tenantID] = map[string]interface{}{
			"max_gpus":           quota.MaxGPUs,
			"used_gpus":          quota.UsedGPUs,
			"max_memory_per_gpu": quota.MaxMemoryPerGPU,
			"usage_percent":      float64(quota.UsedGPUs) / float64(quota.MaxGPUs) * 100,
		}
	}
	stats["tenants"] = tenantStats

	return stats
}
