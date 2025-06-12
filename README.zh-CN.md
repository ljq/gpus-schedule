# GPU算力调度系统

## 项目概述

### 一个极简的桌面级小型GPUs站GPU调度程序实现方案(Minimalist GPU Scheduler)，未经充分验证，请勿用于生产环境！

本项目是一个精简的本地化GPU算力调度系统，为多张NVIDIA 4090显卡环境设计。系统提供了GPU资源管理、多租户算力隔离、动态资源分配以及资源监测功能，并以deepseek-7b模型调用为示例案例。

## 系统架构

系统采用分层架构设计：

- **核心层**：GPU资源管理和调度
- **接口层**：提供标准的GPU算力调用API
- **监控层**：GPU资源监测系统
- **应用层**：示例应用（deepseek-7b调用案例）

## 关键组件

### GPU资源管理器
- 负责发现和管理多张NVIDIA 4090显卡
- 通过YAML配置文件参数化配置显卡数量和属性
- 使用CUDA驱动接口与GPU硬件交互

### 调度系统
- 实现多租户算力隔离
- 动态分配GPU资源，确保算力使用率最大化
- 支持显卡编号和单租户算力动态分配

### 标准API接口
- 提供简洁统一的GPU算力调用接口
- 支持不同应用程序（如deepseek-7b）调用GPU资源

### 资源监测系统
- 实时监控GPU使用情况
- 提供基本的资源使用统计和报告

## 技术选择

- **编程语言**：Golang（尽量避免使用第三方库）
- **配置格式**：YAML
- **系统环境**：Debian系统

## 项目结构

```
/
├── internal/               # 内部包
│   ├── auth/              # 认证相关
│   ├── config/            # 配置管理
│   ├── gpu/               # GPU资源管理
│   ├── monitor/           # 监控系统
│   └── scheduler/         # 调度算法实现
├── pkg/                    # 公共包
│   └── api/               # API接口定义
├── examples/               # 调用案例
│   └── client/            # 客户端示例
├── configs/                # 配置文件
│   └── scheduler.yaml     # 调度器配置
├── web/                    # Web界面
│   └── static/            # 静态资源
├── doc/                    # 文档
│   └── readme.txt         # 文档描述
├── README.md              # 英文文档
└── README.zh-CN.md        # 中文文档
```

## 实现步骤

1. **基础设施搭建**：
   - 创建项目结构和目录
   - 设计并实现配置文件格式和加载机制
   - 搭建基本的日志和错误处理框架

2. **GPU资源管理**：
   - 实现GPU设备发现和初始化机制
   - 开发设备信息收集和状态更新功能
   - 实现资源分配和释放机制

3. **调度系统**：
   - 实现多租户隔离机制
   - 开发基于优先级的动态资源分配算法
   - 实现任务队列和调度循环
   - 添加任务状态管理和超时处理

4. **API接口**：
   - 设计RESTful API接口规范
   - 实现任务提交、查询和管理接口
   - 添加用户认证和权限控制
   - 提供SDK或客户端库

5. **监控系统**：
   - 实现GPU资源实时监测功能
   - 开发指标收集和历史记录功能
   - 提供监控API和简易Web界面
   - 实现告警机制

6. **示例应用**：
   - 实现deepseek-7b模型调用案例
   - 开发客户端示例程序
   - 编写使用文档和示例说明

## 关键技术点

1. **GPU资源隔离**：使用CUDA上下文或类似机制实现多租户隔离
2. **动态调度算法**：根据任务优先级和资源需求动态分配GPU
3. **性能优化**：最小化调度开销，提高资源利用率
4. **容错机制**：处理GPU故障和任务失败情况
5. **安全机制**：实现租户认证和资源访问控制

## 注意事项

- 不使用Docker，直接在主机上管理GPU资源
- 保持设计简洁，避免过度设计
- 尽量减少第三方依赖，除非必要
- 确保系统可横向扩展，支持更多GPU设备
- 优先考虑系统稳定性和资源隔离性

## 使用说明

### 安装

1. 克隆仓库：
   ```bash
   git clone https://gpus-schedule.git
   cd gpus-schedule
   ```

2. 编译项目：
   ```bash
   make build
   ```

3. 配置系统：
   - 编辑 `configs/scheduler.yaml` 文件，根据实际环境配置GPU设备和调度策略
   - 配置认证信息和租户权限

### 启动服务

```bash
# 启动调度器服务
./bin/scheduler --config configs/scheduler.yaml
```

### API使用

系统提供RESTful API接口，可通过HTTP请求进行任务提交和管理：

1. 提交任务：
   ```bash
   curl -X POST http://localhost:8080/api/tasks \
     -H "Content-Type: application/json" \
     -d '{"tenant_id":"tenant-1","name":"test-task","gpu_request":1,"memory_mb":4096,"priority":50}'
   ```

2. 查询任务状态：
   ```bash
   curl http://localhost:8080/api/tasks/{task_id}
   ```

3. 查看系统资源状态：
   ```bash
   curl http://localhost:8080/api/monitor/metrics
   ```

### 客户端示例

项目提供了示例客户端，展示如何使用API接口提交GPU任务：

```bash
# 运行示例客户端
./bin/client --api http://localhost:8080 --tenant tenant-1 --tasks 5
```

### 监控界面

系统提供简易的Web监控界面，可通过浏览器访问：

```
http://localhost:8080/
```

### 更多文档

详细的API文档、配置说明和开发指南请参考[doc/文档目录](./doc/)。