package event

import (
	"encoding/json"
	"fmt"
	"potAgent/common"
	"potAgent/global"
	"potAgent/logger"
	"time"
)

// 事件字段定义
type Event struct {
	Timestamp     string                 `json:"timestamp"`
	EventCategory string                 `json:"event_category"`
	EventType     string                 `json:"event_type"`
	SrcIP         string                 `json:"src_ip"`
	DstIP         string                 `json:"dst_ip"`
	IPProtocol    string                 `json:"ip_protocol"`
	SrcPort       uint16                 `json:"src_port"`
	DstPort       uint16                 `json:"dst_port"`
	Details       map[string]interface{} `json:"details"`
	//Alert         interface{}            `json:"alert"`
}

// NewEvent 构造通用事件，收敛各服务中重复的事件构建样板代码。
// 当前各服务均为 TCP，故 IPProtocol 固定为 tcp。
func NewEvent(category, eventType string, src, dst common.Addr, details map[string]interface{}) *Event {
	return &Event{
		Timestamp:     time.Now().Format(time.DateTime),
		EventCategory: category,
		EventType:     eventType,
		SrcIP:         src.IP,
		DstIP:         dst.IP,
		IPProtocol:    "tcp",
		SrcPort:       src.Port,
		DstPort:       dst.Port,
		Details:       details,
	}
}

var (
	fileRun, kafkaRun bool
	c                 chan string
	c_kaf             chan string
)

// 事件记录初始化
func EventInit(opt *global.Options) error {
	if newFilePusher(opt) {
		c = make(chan string, 1000)
		fileRun = true
		logger.Log.Info("file pusher init success")
	} else if opt.Outputs.File.Enable {
		// 启用了却初始化失败
		return fmt.Errorf("error init file pusher")
	}

	if newKafkaPusher(opt) {
		c_kaf = make(chan string, 1000)
		kafkaRun = true
		logger.Log.Info("kafka pusher init success")
	} else if opt.Outputs.Kafka.Enable {
		// 启用了却初始化失败
		return fmt.Errorf("error init kafka pusher")
	}

	return nil
}

func EventPush(event *Event) error {
	if !fileRun && !kafkaRun {
		return nil
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if fileRun {
		c <- string(eventBytes)
	}
	if kafkaRun {
		c_kaf <- string(eventBytes)
	}
	return nil
}

func EventClose() error {
	defer close(c)
	defer close(c_kaf)
	fileClose()
	closeKafka()
	return nil
}
