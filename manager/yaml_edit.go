package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"potAgent/config"
	"potAgent/global"

	"gopkg.in/yaml.v3"
)

var enableLinePattern = regexp.MustCompile(`^(\s*enable\s*:\s*)(true|false|True|False|TRUE|FALSE)(\s*(?:#.*)?)$`)

// scan 返回 services_dir 下全部 yaml 的绝对路径（与 common.FindConfigFile 行为一致）。
func (m *Manager) scan() ([]string, error) {
	var files []string

	err := filepath.Walk(m.dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".yaml") {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

func (m *Manager) rel(path string) string {
	rel, err := filepath.Rel(m.dir, path)

	if err != nil {
		return filepath.Base(path)
	}

	return rel
}

// parseBaseFile 用 yaml.v3 解析基础字段，并返回文件内容摘要。
// 不使用 config 包：它在解析失败时直接 panic。
func parseBaseFile(path string) (global.ServiceBaseConfig, string, error) {
	var base global.ServiceBaseConfig

	data, err := os.ReadFile(path)
	if err != nil {
		return base, "", fmt.Errorf("读取失败: %w", err)
	}

	if err := yaml.Unmarshal(data, &base); err != nil {
		return base, hashOf(data), fmt.Errorf("YAML 语法错误: %w", err)
	}

	if base.Protocol == "" {
		return base, hashOf(data), fmt.Errorf("缺少必填字段 protocol")
	}

	return base, hashOf(data), nil
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:8])
}

// safeReadOptions 复用项目原有的 viper 读取逻辑，但把 panic 转成 error，
// 避免一个坏 yaml 把整个进程带走。
func safeReadOptions(path string, target interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("解析服务配置失败: %v", r)
		}
	}()

	viperConf, vErr := config.YamlConfigHandle(path)
	if vErr != nil {
		return vErr
	}

	return config.ReadConfigFile(viperConf, target)
}

// rewriteEnable 只改 enable 那一行，保留文件中的注释与排版。
func rewriteEnable(path string, enabled bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", path, err)
	}

	info, statErr := os.Stat(path)
	mode := os.FileMode(0o644)
	if statErr == nil {
		mode = info.Mode()
	}

	lines := strings.Split(string(data), "\n")
	value := strconv.FormatBool(enabled)
	replaced := false
	insertAt := -1

	for i, line := range lines {
		if matched := enableLinePattern.FindStringSubmatch(line); matched != nil {
			lines[i] = matched[1] + value + matched[3]
			replaced = true
			break
		}
		if insertAt < 0 && strings.HasPrefix(line, "protocol:") {
			insertAt = i + 1
		}
	}

	if !replaced {
		line := fmt.Sprintf("enable: %s", value)
		if insertAt < 0 {
			lines = append(lines, line)
		} else {
			lines = append(lines[:insertAt], append([]string{line}, lines[insertAt:]...)...)
		}
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}

	return nil
}
