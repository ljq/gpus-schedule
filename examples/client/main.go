// 示例客户端，展示如何使用API接口提交GPU任务
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"
)

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
}

func main() {
	// 解析命令行参数
	apiURL := flag.String("api", "http://localhost:8080", "API服务器地址")
	tenantID := flag.String("tenant", "tenant-1", "租户ID")
	numTasks := flag.Int("tasks", 5, "要提交的任务数量")
	interval := flag.Int("interval", 2, "任务提交间隔(秒)")
	monitor := flag.Bool("monitor", true, "是否监控任务状态")
	flag.Parse()

	// 初始化随机数生成器
	rand.Seed(time.Now().UnixNano())

	// 提交任务
	taskIDs := make([]string, 0, *numTasks)
	for i := 0; i < *numTasks; i++ {
		// 创建任务请求
		taskReq := TaskRequest{
			TenantID:    *tenantID,
			Name:        fmt.Sprintf("task-%d", i+1),
			Description: fmt.Sprintf("示例任务 #%d", i+1),
			GPURequest:  1,                  // 请求1个GPU
			MemoryMB:    4 * 1024,           // 请求4GB显存
			Priority:    rand.Intn(100) + 1, // 随机优先级(1-100)
			Timeout:     300,                // 5分钟超时
		}

		// 提交任务
		taskID, err := submitTask(*apiURL, taskReq)
		if err != nil {
			log.Printf("提交任务 %s 失败: %v", taskReq.Name, err)
			continue
		}

		taskIDs = append(taskIDs, taskID)
		log.Printf("提交任务 %s 成功，任务ID: %s", taskReq.Name, taskID)

		// 等待指定间隔
		if i < *numTasks-1 {
			time.Sleep(time.Duration(*interval) * time.Second)
		}
	}

	// 如果不需要监控，直接退出
	if !*monitor || len(taskIDs) == 0 {
		return
	}

	// 监控任务状态
	log.Printf("开始监控任务状态...")
	monitorTasks(*apiURL, taskIDs)
}

// 提交任务
func submitTask(apiURL string, task TaskRequest) (string, error) {
	// 将任务请求转换为JSON
	taskJSON, err := json.Marshal(task)
	if err != nil {
		return "", fmt.Errorf("序列化任务请求失败: %v", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/tasks", apiURL), bytes.NewBuffer(taskJSON))
	if err != nil {
		return "", fmt.Errorf("创建HTTP请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %v", err)
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("API返回错误: %s, 状态码: %d", string(body), resp.StatusCode)
	}

	// 解析响应
	var taskResp TaskResponse
	if err := json.Unmarshal(body, &taskResp); err != nil {
		return "", fmt.Errorf("解析响应失败: %v", err)
	}

	return taskResp.ID, nil
}

// 监控任务状态
func monitorTasks(apiURL string, taskIDs []string) {
	// 创建HTTP客户端
	client := &http.Client{}

	// 任务状态计数
	pending := len(taskIDs)
	running := 0
	completed := 0
	cancelled := 0
	failed := 0

	// 任务ID到名称的映射
	taskNames := make(map[string]string)

	// 监控循环
	for pending+running > 0 {
		// 更新所有任务状态
		for _, taskID := range taskIDs {
			// 获取任务状态
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/tasks/%s", apiURL, taskID), nil)
			if err != nil {
				log.Printf("创建HTTP请求失败: %v", err)
				continue
			}

			// 发送请求
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("发送HTTP请求失败: %v", err)
				continue
			}

			// 读取响应
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Printf("读取响应失败: %v", err)
				continue
			}

			// 检查响应状态码
			if resp.StatusCode != http.StatusOK {
				log.Printf("API返回错误: %s, 状态码: %d", string(body), resp.StatusCode)
				continue
			}

			// 解析响应
			var taskResp TaskResponse
			if err := json.Unmarshal(body, &taskResp); err != nil {
				log.Printf("解析响应失败: %v", err)
				continue
			}

			// 保存任务名称
			taskNames[taskID] = taskResp.Name

			// 输出任务状态变化
			statusChanged := false
			switch taskResp.Status {
			case "pending":
				// 任务仍在等待中
			case "running":
				// 任务开始运行
				if len(taskResp.DeviceIDs) > 0 {
					log.Printf("任务 %s (%s) 开始运行，分配的GPU: %v", taskResp.Name, taskID, taskResp.DeviceIDs)
					statusChanged = true
					pending--
					running++
				}
			case "completed":
				// 任务完成
				if running > 0 {
					log.Printf("任务 %s (%s) 已完成", taskResp.Name, taskID)
					statusChanged = true
					running--
					completed++
				} else if pending > 0 {
					log.Printf("任务 %s (%s) 已完成", taskResp.Name, taskID)
					statusChanged = true
					pending--
					completed++
				}
			case "cancelled":
				// 任务被取消
				if running > 0 {
					log.Printf("任务 %s (%s) 已取消", taskResp.Name, taskID)
					statusChanged = true
					running--
					cancelled++
				} else if pending > 0 {
					log.Printf("任务 %s (%s) 已取消", taskResp.Name, taskID)
					statusChanged = true
					pending--
					cancelled++
				}
			case "failed":
				// 任务失败
				if running > 0 {
					log.Printf("任务 %s (%s) 已失败", taskResp.Name, taskID)
					statusChanged = true
					running--
					failed++
				} else if pending > 0 {
					log.Printf("任务 %s (%s) 已失败", taskResp.Name, taskID)
					statusChanged = true
					pending--
					failed++
				}
			}

			// 如果状态发生变化，输出当前统计信息
			if statusChanged {
				log.Printf("任务统计: 等待中: %d, 运行中: %d, 已完成: %d, 已取消: %d, 已失败: %d",
					pending, running, completed, cancelled, failed)
			}
		}

		// 等待一段时间再检查
		time.Sleep(2 * time.Second)
	}

	// 所有任务都已处理完毕
	log.Printf("所有任务处理完毕，最终统计: 已完成: %d, 已取消: %d, 已失败: %d",
		completed, cancelled, failed)
}
