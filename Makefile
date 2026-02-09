# Runixo Agent Makefile

VERSION ?= v0.1.0
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BINARY_NAME := runixo-agent
BUILD_DIR := ../dist

# Go 参数
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED := 0

# 编译标志
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

.PHONY: all build clean test install uninstall run help

all: build

## build: 构建当前平台的二进制文件
build:
	@echo "构建 $(BINARY_NAME) $(VERSION) for $(GOOS)/$(GOARCH)..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/agent
	@echo "构建完成: $(BINARY_NAME)"

## build-all: 构建所有平台
build-all:
	@echo "构建所有平台..."
	@cd .. && bash scripts/build.sh $(VERSION)

## clean: 清理构建产物
clean:
	@echo "清理..."
	@rm -f $(BINARY_NAME)
	@rm -rf $(BUILD_DIR)

## test: 运行测试
test:
	@echo "运行测试..."
	@go test -v ./...

## test-coverage: 运行测试并生成覆盖率报告
test-coverage:
	@echo "运行测试覆盖率..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告: coverage.html"

## install: 安装到系统
install: build
	@echo "安装到 /usr/local/bin..."
	@sudo cp $(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "安装完成"

## uninstall: 从系统卸载
uninstall:
	@echo "卸载..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "卸载完成"

## run: 运行 Agent (开发模式)
run: build
	@ENV=development ./$(BINARY_NAME) -config config.example.yaml

## gen-token: 生成认证令牌
gen-token: build
	@./$(BINARY_NAME) --gen-token

## deps: 下载依赖
deps:
	@echo "下载依赖..."
	@go mod download
	@go mod tidy

## lint: 代码检查
lint:
	@echo "代码检查..."
	@golangci-lint run ./...

## fmt: 格式化代码
fmt:
	@echo "格式化代码..."
	@go fmt ./...

## help: 显示帮助
help:
	@echo "Runixo Agent Makefile"
	@echo ""
	@echo "用法: make [target]"
	@echo ""
	@echo "目标:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
