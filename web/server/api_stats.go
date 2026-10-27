package server

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"potAgent/logger"
)

func round1(value float64) float64 {
	return math.Round(value*10) / 10
}

func deltaPercent(current, previous int64) float64 {
	if previous <= 0 {
		return 0
	}

	return round1(float64(current-previous) / float64(previous) * 100)
}

func atoiDefault(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return parsed
}

// handleStatsReset 清空统计库里的历史数据（event_hourly / source_hourly），
// 并把聚合游标推到当前 event.log 末尾，避免清空后又被历史日志重新填满。
func (s *Server) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	cursor := s.reader.size()

	if err := s.stats.Reset(cursor); err != nil {
		logger.Log.Errorf("清空统计失败: %v", err)
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	logger.Log.Warnf("统计数据已被清空，聚合游标重置为 %d", cursor)
	writeOK(w, map[string]interface{}{"ok": true, "logOffset": cursor})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	yesterdayStart := todayStart.AddDate(0, 0, -1)

	today := s.stats.sumSince(todayStart, time.Time{})
	yesterdaySame := s.stats.sumSince(yesterdayStart, yesterdayStart.Add(now.Sub(todayStart)))

	since24 := now.Add(-24 * time.Hour)
	since48 := now.Add(-48 * time.Hour)
	sources24 := s.stats.distinctSources(since24, time.Time{})
	sourcesPrev := s.stats.distinctSources(since48, since24)

	sourcesDelta := 0
	if sourcesPrev > 0 {
		sourcesDelta = int(math.Round(float64(sources24-sourcesPrev) / float64(sourcesPrev) * 100))
	}

	snapshot := s.mgr.Snapshot()
	active := 0

	for _, item := range snapshot {
		if item.Running {
			active++
		}
	}

	var lastLogAt *string
	if mod := s.reader.ModTime(); !mod.IsZero() {
		value := mod.Format(time.DateTime)
		lastLogAt = &value
	}

	writeOK(w, overviewStats{
		TotalEvents:        s.stats.totalEvents(),
		TodayEvents:        today,
		TodayDeltaPercent:  deltaPercent(today, yesterdaySame),
		UniqueSources:      sources24,
		UniqueSourcesDelta: sourcesDelta,
		ActiveServices:     active,
		TotalServices:      len(snapshot),
		Connections:        0,
		LogFileSize:        s.reader.size(),
		LastLogAt:          lastLogAt,
		UptimeSeconds:      int64(s.mgr.Uptime().Seconds()),
	})
}

func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("range") {
	case "day":
		writeOK(w, s.dailyTrend(14))
	case "week":
		writeOK(w, s.weeklyTrend(8))
	default:
		writeOK(w, s.hourlyTrend(24))
	}
}

func (s *Server) hourlyTrend(hours int) trendSeries {
	now := time.Now()
	start := now.Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour)
	buckets := s.stats.bucketSeries(start)

	points := make([]trendPoint, 0, hours)
	var total int64
	var peak trendPoint

	for i := 0; i < hours; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		item := buckets[at.Unix()]
		point := trendPoint{
			Label:   at.Format("15:04"),
			At:      at.Format(time.DateTime),
			Value:   item.Count,
			Sources: item.Sources,
		}

		if point.Value > peak.Value {
			peak = point
		}

		total += point.Value
		points = append(points, point)
	}

	previous := s.stats.sumSince(start.Add(-time.Duration(hours)*time.Hour), start)

	return trendSeries{
		Range:        "hour",
		Points:       points,
		Total:        total,
		DeltaPercent: deltaPercent(total, previous),
		PeakLabel:    peak.Label,
	}
}

func (s *Server) dailyTrend(days int) trendSeries {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).
		AddDate(0, 0, -(days - 1))

	type dayAcc struct {
		value   int64
		sources int64
	}

	buckets := s.stats.bucketSeries(start)
	daily := make(map[string]*dayAcc)

	for bucket, item := range buckets {
		key := time.Unix(bucket, 0).In(time.Local).Format("2006-01-02")
		if daily[key] == nil {
			daily[key] = &dayAcc{}
		}

		daily[key].value += item.Count
		if item.Sources > daily[key].sources {
			daily[key].sources = item.Sources
		}
	}

	points := make([]trendPoint, 0, days)
	var total int64
	var peak trendPoint

	for i := 0; i < days; i++ {
		at := start.AddDate(0, 0, i)
		item := daily[at.Format("2006-01-02")]
		point := trendPoint{
			Label: at.Format("1/2"),
			At:    at.Format(time.DateTime),
		}

		if item != nil {
			point.Value = item.value
			point.Sources = item.sources
		}

		if point.Value > peak.Value {
			peak = point
		}

		total += point.Value
		points = append(points, point)
	}

	previous := s.stats.sumSince(start.AddDate(0, 0, -days), start)

	return trendSeries{
		Range:        "day",
		Points:       points,
		Total:        total,
		DeltaPercent: deltaPercent(total, previous),
		PeakLabel:    peak.Label,
	}
}

func startOfWeek(at time.Time) time.Time {
	weekday := int(at.Weekday())
	if weekday == 0 {
		weekday = 7
	}

	day := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, at.Location())

	return day.AddDate(0, 0, -(weekday - 1))
}

func (s *Server) weeklyTrend(weeks int) trendSeries {
	now := time.Now()
	currentWeek := startOfWeek(now)
	start := currentWeek.AddDate(0, 0, -7*(weeks-1))

	type weekAcc struct {
		value   int64
		sources int64
	}

	buckets := s.stats.bucketSeries(start)
	weekly := make(map[int64]*weekAcc)

	for bucket, item := range buckets {
		weekStart := startOfWeek(time.Unix(bucket, 0).In(time.Local)).Unix()
		if weekly[weekStart] == nil {
			weekly[weekStart] = &weekAcc{}
		}

		weekly[weekStart].value += item.Count
		if item.Sources > weekly[weekStart].sources {
			weekly[weekStart].sources = item.Sources
		}
	}

	points := make([]trendPoint, 0, weeks)
	var total int64
	var peak trendPoint

	for i := 0; i < weeks; i++ {
		at := start.AddDate(0, 0, 7*i)
		item := weekly[at.Unix()]
		offset := weeks - 1 - i

		label := "本周"
		if offset == 1 {
			label = "上周"
		} else if offset > 1 {
			label = "W-" + strconv.Itoa(offset)
		}

		point := trendPoint{
			Label: label,
			At:    at.Format(time.DateTime),
		}

		if item != nil {
			point.Value = item.value
			point.Sources = item.sources
		}

		if point.Value > peak.Value {
			peak = point
		}

		total += point.Value
		points = append(points, point)
	}

	previous := s.stats.sumSince(start.AddDate(0, 0, -7*weeks), start)

	return trendSeries{
		Range:        "week",
		Points:       points,
		Total:        total,
		DeltaPercent: deltaPercent(total, previous),
		PeakLabel:    peak.Label,
	}
}

func (s *Server) handleTopSources(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 6)
	writeOK(w, s.stats.TopSources(limit, time.Now().Add(-24*time.Hour)))
}
