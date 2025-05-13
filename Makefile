# 定义编译器
GO=go

# 获取编译时间和编译版本
BUILD_TIME=$(shell date +"%Y-%m-%d %H:%M:%S")
BUILD_VERSION=$(shell git describe --tags --always --dirty)
NAME=PotAgent

# 默认目标
all: debug


debug:
	$(GO) build -o $(NAME) -ldflags "-X main.buildTime='$(BUILD_TIME)' -X main.buildVersion='$(BUILD_VERSION)' -X main.buildMode='debug'" -gcflags "all=-N -l"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Build Version: $(BUILD_VERSION)"


release:
	$(GO) build -o $(NAME) -ldflags "-X main.buildTime='$(BUILD_TIME)' -X main.buildVersion='$(BUILD_VERSION)'"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Build Version: $(BUILD_VERSION)"


clean:
	rm -f $(NAME) *.log


.PHONY: all debug release clean