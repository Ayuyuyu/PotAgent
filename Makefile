# 定义编译器
GO=go

# 获取编译时间和编译版本
# 注意：BUILD_TIME 不能含空格（ldflags 的 -X 值会被按空格切分），故用 T 分隔
BUILD_TIME=$(shell date +"%Y-%m-%dT%H:%M:%S")
BUILD_VERSION=$(shell git describe --tags --always --dirty)
NAME=PotAgent

# 待 gofmt 检查的所有 .go 文件
GO_FILES := $(shell find . -name '*.go' -not -path './.git/*')

# 管理台前端目录与嵌入位置
WEB_DIR := web/frontend
WEB_DIST := web/server/dist

# 默认目标
all: web debug

# 构建管理台前端并复制到 web/server/dist（之后重新编译二进制即可嵌入）
web:
	cd $(WEB_DIR) && npm run build
	rm -rf $(WEB_DIST)
	mkdir -p $(WEB_DIST)
	cp -r $(WEB_DIR)/dist/. $(WEB_DIST)/
	@touch $(WEB_DIST)/.gitkeep
	@echo "前端已构建到 $(WEB_DIST)，接着执行 make release 或 make debug"

# 只装前端依赖（首次或 package.json 变更后）
web-deps:
	cd $(WEB_DIR) && npm install --no-audit --no-fund

# 开发态前端（Vite dev server，/api 代理到 127.0.0.1:58090）
web-dev:
	cd $(WEB_DIR) && npm run dev


debug:
	$(GO) build -o $(NAME) -ldflags "-X main.buildTime=$(BUILD_TIME) -X main.buildVersion=$(BUILD_VERSION) -X main.buildMode=debug" -gcflags "all=-N -l" ./cmd/potagent
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Build Version: $(BUILD_VERSION)"


release:
	$(GO) build -o $(NAME) -ldflags "-X main.buildTime=$(BUILD_TIME) -X main.buildVersion=$(BUILD_VERSION)" ./cmd/potagent
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Build Version: $(BUILD_VERSION)"


clean:
	rm -f $(NAME) *.log


# 格式化
fmt:
	@$(GO) fmt ./...

# 静态检查
vet:
	@$(GO) vet ./...

# 运行测试
test:
	@$(GO) test ./...

# 仅检查 gofmt 是否合规（不自动改，不合规则报错列出文件）
gofmt-check:
	@unformatted=$$(gofmt -l $(GO_FILES)); \
	if [ -n "$$unformatted" ]; then \
		echo "以下文件未通过 gofmt，请运行 'make fmt'："; \
		echo "$$unformatted"; \
		exit 1; \
	else \
		echo "gofmt OK"; \
	fi

# 一键质量检查：gofmt 校验 + vet + test
check: gofmt-check vet test


.PHONY: all debug release clean fmt vet test gofmt-check check web web-deps web-dev