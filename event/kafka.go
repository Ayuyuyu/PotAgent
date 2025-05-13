package event

import (
	"fmt"
	"potAgent/global"
	"potAgent/logger"
	"time"

	"github.com/IBM/sarama"
)

var producer sarama.SyncProducer
var topic string

func newKafkaPusher(opt *global.Options) bool {
	if !opt.Outputs.Kafka.Enable {
		return false
	}

	if len(opt.Outputs.Kafka.Topic) == 0 {
		logger.Log.Error("topic 必须设置")
		return false
	}

	if len(opt.Outputs.Kafka.Host) == 0 {
		logger.Log.Error("host 必须设置")
		return false
	}

	if opt.Outputs.Kafka.Port == 0 {
		logger.Log.Error("port 必须设置")
		return false
	}
	bootstrapServers := fmt.Sprintf("%v:%v", opt.Outputs.Kafka.Host, opt.Outputs.Kafka.Port)
	logger.Log.Infoln("outputs.kafka.bootstrap_services:", bootstrapServers)
	logger.Log.Infoln("outputs.kafka.topic:", opt.Outputs.Kafka.Topic)
	kafConfig := sarama.NewConfig()
	kafConfig.Producer.Return.Successes = true
	kafConfig.Producer.Return.Errors = true
	kafConfig.Producer.Partitioner = sarama.NewRandomPartitioner
	topic = opt.Outputs.Kafka.Topic

	producer_sync, err := sarama.NewSyncProducer([]string{bootstrapServers}, kafConfig)
	if err != nil {
		time.Sleep(5 * time.Second)
		logger.Log.Panic(err.Error())
	}
	producer = producer_sync
	go func() {
		for e := range c_kaf {
			if e == "" {
				return
			}
			err := produce(e)
			if err != nil {
				logger.Log.Error(err)
			}
		}
	}()
	return true
}

func produce(data string) error {
	_, _, err := producer.SendMessage(&sarama.ProducerMessage{Topic: topic, Key: nil, Value: sarama.StringEncoder(data)})
	if err != nil {
		logger.Log.Panic(err)
	}

	return nil

}

func closeKafka() {
	producer.Close()
}
