// Package api 提供GPU算力调度系统的API接口
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gpus-schedule/internal/auth"
	"gpus-schedule/internal/scheduler"
)

// APIServer API服务器
type APIServer struct {
	scheduler      *scheduler.Scheduler
	server         *http.Server
	authManager    *auth.AuthManager
	authEnabled    bool
	authMiddleware *AuthMiddleware
}

// TaskRequest 任务请求
type TaskRequest struct {
	TenantID    string `json:"tenant_id"`   // 租户ID
	Name        string `json:"name"`        // 任务名称
	Description string `json:"description"` // 任务描述
	GPURequest  int    `json:"gpu_request"` // 请求的GPU数量
	MemoryMB    int64  `json:"memory_mb"`   // 请求的内存(MB)
	Priority    int    `json:"priority"`    // 优先级(1-100)
	Timeout     int    `json:"timeout"`     // 超时时间(秒)
}

// TaskResponse 任务响应
type TaskResponse struct {
	ID          string    `json:"id"`          // 任务ID
	TenantID    string    `json:"tenant_id"`   // 租户ID
	Name        string    `json:"name"`        // 任务名称
	Description string    `json:"description"` // 任务描述
	Status      string    `json:"status"`      // 任务状态
	GPURequest  int       `json:"gpu_request"` // 请求的GPU数量
	MemoryMB    int64     `json:"memory_mb"`   // 请求的内存(MB)
	Priority    int       `json:"priority"`    // 优先级
	CreatedAt   time.Time `json:"created_at"`  // 创建时间
	StartedAt   time.Time `json:"started_at"`  // 开始时间
	FinishedAt  time.Time `json:"finished_at"` // 完成时间
	DeviceIDs   []int     `json:"device_ids"`  // 分配的设备ID
	Timeout     int       `json:"timeout"`     // 超时时间(秒)
	CreatedBy   string    `json:"created_by"`  // 创建者ID
}

// ErrorResponse 错误响应
type ErrorResponse struct {
	Error string `json:"error"` // 错误信息
}

// NewAPIServer 创建新的API服务器
func NewAPIServer(scheduler *scheduler.Scheduler, host string, port int, authManager *auth.AuthManager, authEnabled bool) *APIServer {
	server := &APIServer{
		scheduler: scheduler,
		server: &http.Server{
			Addr: fmt.Sprintf("%s:%d", host, port),
		},
		authManager: authManager,
		authEnabled: authEnabled,
	}

	// 如果启用认证，创建认证中间件
	if authEnabled && authManager != nil {
		server.authMiddleware = NewAuthMiddleware(authManager, authEnabled)
	}

	// 设置路由
	mux := http.NewServeMux()

	// 认证相关路由
	if server.authEnabled {
		mux.HandleFunc("/api/login", server.authMiddleware.HandleLogin)
		mux.HandleFunc("/api/user", server.wrapWithAuth(server.authMiddleware.HandleGetCurrentUser))
		mux.HandleFunc("/api/tenant", server.wrapWithAuth(server.authMiddleware.HandleGetTenantInfo))
	}

	// 任务相关路由
	mux.HandleFunc("/api/tasks", server.wrapWithAuth(server.handleTasks))
	mux.HandleFunc("/api/tasks/", server.wrapWithAuth(server.handleTaskDetail))
	mux.HandleFunc("/api/tenants/", server.wrapWithTenantCheck(server.handleTenantTasks))
	mux.HandleFunc("/api/stats", server.wrapWithAuth(server.handleStats))

	server.server.Handler = mux

	return server
}

// Start 启动API服务器
func (s *APIServer) Start() error {
	return s.server.ListenAndServe()
}

// Stop 停止API服务器
func (s *APIServer) Stop() error {
	return s.server.Close()
}

// handleTasks 处理任务相关请求
func (s *APIServer) handleTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取所有任务
		s.handleGetAllTasks(w, r)
	case http.MethodPost:
		// 创建新任务
		s.handleCreateTask(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTaskDetail 处理单个任务的详细信息
func (s *APIServer) handleTaskDetail(w http.ResponseWriter, r *http.Request) {
	// 从URL中提取任务ID
	taskID := r.URL.Path[len("/api/tasks/"):]
	if taskID == "" {
		http.Error(w, "Task ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// 获取任务详情
		s.handleGetTask(w, r, taskID)
	case http.MethodDelete:
		// 取消任务
		s.handleCancelTask(w, r, taskID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTenantTasks 处理租户任务
func (s *APIServer) handleTenantTasks(w http.ResponseWriter, r *http.Request) {
	// 从URL中提取租户ID
	tenantID := r.URL.Path[len("/api/tenants/"):]
	if tenantID == "" {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// 获取租户的所有任务
		s.handleGetTenantTasks(w, r, tenantID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStats 处理统计信息
func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取统计信息
		s.handleGetStats(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetAllTasks 获取所有任务
func (s *APIServer) handleGetAllTasks(w http.ResponseWriter, r *http.Request) {
	// 这里应该实现获取所有任务的逻辑
	// 由于当前调度器没有提供获取所有任务的方法，这里暂时返回空列表
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]TaskResponse{})
}

// handleCreateTask 创建新任务
func (s *APIServer) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	// 解析请求体
	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request format"})
		return
	}

	// 如果启用了认证，验证租户ID
	if s.authEnabled {
		// 从请求上下文中获取令牌声明
		claims, ok := auth.ClaimsFromContext(r.Context())
		if ok {
			// 非管理员用户只能为自己的租户创建任务
			if claims.Role != auth.RoleAdmin && req.TenantID != claims.TenantID {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "无权为其他租户创建任务"})
				return
			}

			// 如果未指定租户ID，使用当前用户的租户ID
			if req.TenantID == "" {
				req.TenantID = claims.TenantID
			}
		}
	}

	// 创建任务
	task := &scheduler.Task{
		ID:          fmt.Sprintf("task-%d", time.Now().UnixNano()),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		GPURequest:  req.GPURequest,
		MemoryMB:    req.MemoryMB,
		Priority:    req.Priority,
		Timeout:     req.Timeout,
	}

	// 如果启用了认证，记录创建者信息
	if s.authEnabled {
		if claims, ok := auth.ClaimsFromContext(r.Context()); ok {
			task.CreatedBy = claims.UserID
		}
	}

	// 提交任务
	err := s.scheduler.SubmitTask(task)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	// 返回任务信息
	resp := TaskResponse{
		ID:          task.ID,
		TenantID:    task.TenantID,
		Name:        task.Name,
		Description: task.Description,
		Status:      string(task.Status),
		GPURequest:  task.GPURequest,
		MemoryMB:    task.MemoryMB,
		Priority:    task.Priority,
		CreatedAt:   task.CreatedAt,
		StartedAt:   task.StartedAt,
		FinishedAt:  task.FinishedAt,
		DeviceIDs:   task.DeviceIDs,
		Timeout:     task.Timeout,
		CreatedBy:   task.CreatedBy,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// handleGetTask 获取任务详情
func (s *APIServer) handleGetTask(w http.ResponseWriter, r *http.Request, taskID string) {
	// 获取任务
	task, err := s.scheduler.GetTaskStatus(taskID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	// 返回任务信息
	resp := TaskResponse{
		ID:          task.ID,
		TenantID:    task.TenantID,
		Name:        task.Name,
		Description: task.Description,
		Status:      string(task.Status),
		GPURequest:  task.GPURequest,
		MemoryMB:    task.MemoryMB,
		Priority:    task.Priority,
		CreatedAt:   task.CreatedAt,
		StartedAt:   task.StartedAt,
		FinishedAt:  task.FinishedAt,
		DeviceIDs:   task.DeviceIDs,
		Timeout:     task.Timeout,
		CreatedBy:   task.CreatedBy,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleCancelTask 取消任务
func (s *APIServer) handleCancelTask(w http.ResponseWriter, r *http.Request, taskID string) {
	// 取消任务
	err := s.scheduler.CancelTask(taskID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	// 返回成功
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

// handleGetTenantTasks 获取租户的所有任务
func (s *APIServer) handleGetTenantTasks(w http.ResponseWriter, r *http.Request, tenantID string) {
	// 获取租户任务
	tasks := s.scheduler.GetTenantTasks(tenantID)

	// 转换为响应格式
	resps := make([]TaskResponse, 0, len(tasks))
	for _, task := range tasks {
		resps = append(resps, TaskResponse{
			ID:          task.ID,
			TenantID:    task.TenantID,
			Name:        task.Name,
			Description: task.Description,
			Status:      string(task.Status),
			GPURequest:  task.GPURequest,
			MemoryMB:    task.MemoryMB,
			Priority:    task.Priority,
			CreatedAt:   task.CreatedAt,
			StartedAt:   task.StartedAt,
			FinishedAt:  task.FinishedAt,
			DeviceIDs:   task.DeviceIDs,
			Timeout:     task.Timeout,
			CreatedBy:   task.CreatedBy,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resps)
}

// handleGetStats 获取统计信息
func (s *APIServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	// 获取统计信息
	stats := s.scheduler.GetSchedulerStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// wrapWithAuth 根据认证设置包装处理函数
func (s *APIServer) wrapWithAuth(handler http.HandlerFunc) http.HandlerFunc {
	if !s.authEnabled || s.authMiddleware == nil {
		// 如果未启用认证，直接返回原始处理函数
		return handler
	}

	// 创建一个包装了认证中间件的处理函数
	return func(w http.ResponseWriter, r *http.Request) {
		// 创建一个处理链，先经过认证中间件，然后是原始处理函数
		s.authMiddleware.Authenticate(http.HandlerFunc(handler)).ServeHTTP(w, r)
	}
}

// wrapWithTenantCheck 包装处理函数，添加租户访问检查
func (s *APIServer) wrapWithTenantCheck(handler http.HandlerFunc) http.HandlerFunc {
	if !s.authEnabled || s.authMiddleware == nil {
		// 如果未启用认证，直接返回原始处理函数
		return handler
	}

	// 创建一个包装了租户访问检查的处理函数
	return func(w http.ResponseWriter, r *http.Request) {
		// 创建一个处理链，先经过认证中间件，然后是租户访问检查，最后是原始处理函数
		s.authMiddleware.Authenticate(
			s.authMiddleware.RequireTenantAccess()(http.HandlerFunc(handler)),
		).ServeHTTP(w, r)
	}
}
