# GPU算力调度系统 Makefile

# 变量定义
BINARY_NAME=gpu-scheduler
BINARY_DIR=bin
CMD_DIR=.
CONFIG_DIR=configs
WEB_DIR=web
EXAMPLES_DIR=examples

# Go命令
GO=go
GOBUILD=$(GO) build
GOTEST=$(GO) test
GOFMT=$(GO) fmt
GOLINT=golint
GOVET=$(GO) vet

# 版本信息
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date +%FT%T%z)
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 编译标志
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.CommitHash=$(COMMIT_HASH)"

# 默认目标
.PHONY: all
all: build

# 创建必要的目录
.PHONY: init
init:
	mkdir -p $(BINARY_DIR)
	mkdir -p $(WEB_DIR)/static

# 编译
.PHONY: build
build: init
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) ./
	cp $(CONFIG_DIR)/scheduler.yaml $(BINARY_DIR)/

# 运行
.PHONY: run
run: build
	./$(BINARY_DIR)/$(BINARY_NAME) --config $(CONFIG_DIR)/scheduler.yaml

# 清理
.PHONY: clean
clean:
	rm -rf $(BINARY_DIR)

# 格式化代码
.PHONY: fmt
fmt:
	$(GOFMT) ./...

# 代码检查
.PHONY: lint
lint:
	$(GOLINT) ./...
	$(GOVET) ./...

# 测试
.PHONY: test
test:
	$(GOTEST) -v ./...

# 构建示例客户端
.PHONY: example-client
example-client:
	$(GOBUILD) -o $(BINARY_DIR)/example-client ./$(EXAMPLES_DIR)/client

# 运行示例客户端
.PHONY: run-example-client
run-example-client: example-client
	./$(BINARY_DIR)/example-client --api http://localhost:8080 --tenant tenant-1 --tasks 5

# 帮助
.PHONY: help
help:
	@echo "GPU算力调度系统 Makefile 帮助"
	@echo ""
	@echo "可用目标:"
	@echo "  all             默认目标，等同于build"
	@echo "  init            创建必要的目录"
	@echo "  build           编译项目"
	@echo "  run             运行项目"
	@echo "  clean           清理编译产物"
	@echo "  fmt             格式化代码"
	@echo "  lint            代码检查"
	@echo "  test            运行测试"
	@echo "  example-client  构建示例客户端"
	@echo "  run-example-client 运行示例客户端"
	@echo "  help            显示此帮助信息"