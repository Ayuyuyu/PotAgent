package global

import (
	"fmt"
	"time"
)

type OptionsOutputsFile struct {
	Enable   bool   `mapstructure:"enable"`
	FilePath string `mapstructure:"file_path"`
}

type OptionsOutputsKafka struct {
	Enable bool   `mapstructure:"enable"`
	Host   string `mapstructure:"host"`
	Port   uint16 `mapstructure:"port"`
	Topic  string `mapstructure:"topic"`
}

type OptionsOutputs struct {
	File  OptionsOutputsFile  `mapstructure:"file"`
	Kafka OptionsOutputsKafka `mapstructure:"kafka"`
}

// WebConfig 管理台配置。管理台编译进主进程，但使用独立端口与独立路由树，
// 代码位于 web/server，不与 services 下的蜜罐协议实现混在一起。
type WebConfig struct {
	// 是否随主进程启动管理台
	Enable bool `mapstructure:"enable"`
	// 监听地址，默认仅本机
	Host string `mapstructure:"host"`
	Port uint16 `mapstructure:"port"`
	// 登录账号；Password 支持明文或 "bcrypt:<hash>" 前缀
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	// 统计库路径（相对 CWD），按小时聚合事件
	StatsDBPath string `mapstructure:"stats_db_path"`
	// 会话有效期（分钟）
	SessionTTLMinutes int `mapstructure:"session_ttl_minutes"`
}

func (w WebConfig) Addr() string {
	host := w.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := w.Port
	if port == 0 {
		port = 58090
	}

	return fmt.Sprintf("%s:%d", host, port)
}

func (w WebConfig) SessionTTL() time.Duration {
	if w.SessionTTLMinutes <= 0 {
		return 8 * time.Hour
	}

	return time.Duration(w.SessionTTLMinutes) * time.Minute
}

type Options struct {
	// 服务配置所在的目录
	ServicesDir string `mapstructure:"services_dir"`
	// 日志等级（debug/info/warn/error），留空沿用编译期设定或默认 info
	LogLevel string `mapstructure:"log_level"`
	// 数据推送参数
	Outputs OptionsOutputs `mapstructure:"outputs"`
	// 管理台参数
	Web WebConfig `mapstructure:"web"`
}

type ServiceBaseConfig struct {
	Protocol    string `mapstructure:"protocol"`
	Application string `mapstructure:"application"`
	Enable      bool   `mapstructure:"enable"`
	Host        string `mapstructure:"host"`
	Port        uint16 `mapstructure:"port"`
}
