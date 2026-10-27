package server

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"potAgent/manager"
	"potAgent/services"

	"gopkg.in/yaml.v3"
)

type rawServiceConfig struct {
	Protocol    string `yaml:"protocol"`
	Application string `yaml:"application"`
	Enable      *bool  `yaml:"enable"`
	Host        string `yaml:"host"`
	Port        *int   `yaml:"port"`
}

var lineErrorPattern = regexp.MustCompile(`line (\d+)`)

func fieldLine(content, field string) int {
	for index, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), field+":") {
			return index + 1
		}
	}

	return 0
}

func yamlErrorLine(message string) int {
	if matched := lineErrorPattern.FindStringSubmatch(message); matched != nil {
		if line, err := strconv.Atoi(matched[1]); err == nil {
			return line
		}
	}

	return 0
}

func compactYAMLError(message string) string {
	compact := strings.Join(strings.Fields(strings.ReplaceAll(message, "yaml: unmarshal errors:", "")), " ")

	if len(compact) > 180 {
		return compact[:180] + "…"
	}

	return compact
}

// validateConfig 校验 YAML 语法、必填字段、字段取值范围与端口冲突。
func (s *Server) validateConfig(target string, content string) validationResult {
	result := validationResult{
		Issues:    make([]validationIssue, 0, 4),
		CheckedAt: time.Now().Format(time.DateTime),
	}

	var parsed rawServiceConfig
	if err := yaml.Unmarshal([]byte(content), &parsed); err != nil {
		result.Issues = append(result.Issues, validationIssue{
			Level:   "error",
			Line:    yamlErrorLine(err.Error()),
			Field:   "syntax",
			Message: compactYAMLError(err.Error()),
		})
	} else {
		result.Passed++
	}

	protocol := strings.ToLower(strings.TrimSpace(parsed.Protocol))
	if protocol == "" {
		result.Issues = append(result.Issues, validationIssue{
			Level: "error", Field: "protocol", Message: "缺少必填字段 protocol",
		})
	} else {
		result.Passed++

		if _, err := services.Get(protocol); err != nil {
			result.Issues = append(result.Issues, validationIssue{
				Level:   "warning",
				Line:    fieldLine(content, "protocol"),
				Field:   "protocol",
				Message: "协议 " + protocol + " 未在当前二进制中注册，该实例会被跳过",
			})
		}
	}

	if strings.TrimSpace(parsed.Application) == "" {
		result.Issues = append(result.Issues, validationIssue{
			Level: "error", Field: "application", Message: "缺少必填字段 application",
		})
	} else {
		result.Passed++
	}

	if strings.TrimSpace(parsed.Host) == "" {
		result.Issues = append(result.Issues, validationIssue{
			Level:   "warning",
			Line:    fieldLine(content, "host"),
			Field:   "host",
			Message: "未配置监听地址，建议显式写 host（例如 0.0.0.0）",
		})
	} else {
		result.Passed++
	}

	if parsed.Enable == nil {
		result.Issues = append(result.Issues, validationIssue{
			Level: "error", Field: "enable", Message: "缺少必填字段 enable（true/false）",
		})
	} else {
		result.Passed++
	}

	if parsed.Port == nil {
		result.Issues = append(result.Issues, validationIssue{
			Level: "error", Field: "port", Message: "缺少必填字段 port",
		})
	} else if *parsed.Port < 1 || *parsed.Port > 65535 {
		result.Issues = append(result.Issues, validationIssue{
			Level:   "error",
			Line:    fieldLine(content, "port"),
			Field:   "port",
			Message: "port 必须是 1~65535 之间的整数",
		})
	} else {
		result.Passed++

		if conflict := s.findPortConflict(target, protocol, *parsed.Port); conflict != "" {
			result.Issues = append(result.Issues, validationIssue{
				Level:   "warning",
				Line:    fieldLine(content, "port"),
				Field:   "port",
				Message: "端口已被 " + conflict + " 占用，热加载时该实例会启动失败",
			})
		}
	}

	for _, issue := range result.Issues {
		if issue.Level == "error" {
			result.Valid = false

			return result
		}
	}

	result.Valid = true

	return result
}

func (s *Server) findPortConflict(target, protocol string, port int) string {
	wantUDP := manager.IsUDPProtocol(protocol)

	for _, info := range s.mgr.Snapshot() {
		if info.Rel == target || !info.Enabled {
			continue
		}
		if int(info.Port) != port {
			continue
		}
		if manager.IsUDPProtocol(info.Protocol) != wantUDP {
			continue
		}

		return info.Application + "（" + info.Rel + "）"
	}

	return ""
}
