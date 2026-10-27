package server

import (
	"time"

	"potAgent/logger"
)

const (
	// 单次聚合最多消费的字节数：首次索引大文件时逐步推进，避免启动卡顿
	aggregateBatchBytes = 8 * 1024 * 1024
	aggregateInterval   = 5 * time.Second
)

// aggregateLoop 持续把 event.log 的新增内容折算进小时桶。
func (s *Server) aggregateLoop() {
	ticker := time.NewTicker(aggregateInterval)
	defer ticker.Stop()

	s.aggregateOnce()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.aggregateOnce()
		}
	}
}

func (s *Server) aggregateOnce() {
	// 每次 tick 连续消费多批：首次面对历史大文件时能快速追平，而不是每 5 秒只推进 8MB
	const maxBatches = 8

	for batch := 0; batch < maxBatches; batch++ {
		offset := s.stats.aggregateCursor()

		events, next, truncated, err := s.reader.ReadFrom(offset, aggregateBatchBytes)
		if err != nil {
			logger.Log.Errorf("统计聚合读取日志失败: %v", err)

			return
		}

		if truncated {
			logger.Log.Warnf("event.log 已重置，统计游标回到文件头")
		}

		if next == offset {
			return
		}

		if err := s.stats.Apply(events); err != nil {
			logger.Log.Errorf("统计写入失败: %v", err)

			return
		}

		if err := s.stats.saveAggregateCursor(next); err != nil {
			logger.Log.Errorf("统计游标写入失败: %v", err)

			return
		}

		// 已追到文件尾，无需继续
		if next >= s.reader.size() {
			return
		}
	}
}
