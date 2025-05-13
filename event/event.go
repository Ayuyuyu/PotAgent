package event

import (
	"encoding/json"
	"fmt"
	"potAgent/global"
	"potAgent/logger"
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

var (
	fileRun, kafkaRun bool
	c                 chan string
	c_kaf             chan string
)

// 事件记录初始化
func EventInit(opt *global.Options) error {
	var err error
	if !newFilePusher(opt) {
		err = fmt.Errorf("error init file or filepush not enable")
	} else {
		c = make(chan string, 1000)
		fileRun = true
		logger.Log.Info("file pusher init success")
	}

	if !newKafkaPusher(opt) {
		err = fmt.Errorf("error init kafka or kafkapush not enable")
	} else {
		c_kaf = make(chan string, 1000)
		kafkaRun = true
		logger.Log.Info("kafka pusher init success")
	}

	return err
}

func EventPush(event *Event) error {
	if fileRun && kafkaRun {
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
