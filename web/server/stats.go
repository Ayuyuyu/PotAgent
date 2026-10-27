package server

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// statsStore 负责把 event.log 按小时聚合成可回溯的统计。
type statsStore struct {
	db *sql.DB

	mu       sync.RWMutex
	byProto  map[string]int64
	lastSeen map[string]time.Time
}

const statsSchema = `
CREATE TABLE IF NOT EXISTS event_hourly (
	bucket   INTEGER NOT NULL,
	protocol TEXT    NOT NULL,
	count    INTEGER NOT NULL,
	PRIMARY KEY (bucket, protocol)
);
CREATE TABLE IF NOT EXISTS source_hourly (
	bucket    INTEGER NOT NULL,
	src_ip    TEXT    NOT NULL,
	count     INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	PRIMARY KEY (bucket, src_ip)
);
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

func openStats(path string) (*statsStore, error) {
	if path == "" {
		path = "./potagent_stats.db"
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开统计库失败: %w", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec(statsSchema); err != nil {
		db.Close()

		return nil, fmt.Errorf("初始化统计表失败: %w", err)
	}

	store := &statsStore{
		db:       db,
		byProto:  make(map[string]int64),
		lastSeen: make(map[string]time.Time),
	}

	if err := store.loadProtocolTotals(); err != nil {
		db.Close()

		return nil, err
	}

	return store, nil
}

func (s *statsStore) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

func (s *statsStore) loadProtocolTotals() error {
	rows, err := s.db.Query(`SELECT protocol, SUM(count), MAX(bucket) FROM event_hourly GROUP BY protocol`)
	if err != nil {
		return fmt.Errorf("读取协议统计失败: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			protocol string
			count    int64
			lastAt   sql.NullInt64
		)
		if err := rows.Scan(&protocol, &count, &lastAt); err != nil {
			return err
		}

		s.byProto[protocol] = count
		if lastAt.Valid {
			s.lastSeen[protocol] = time.Unix(lastAt.Int64, 0)
		}
	}

	return rows.Err()
}

func (s *statsStore) aggregateCursor() int64 {
	var value string

	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'log_offset'`).Scan(&value)
	if err != nil {
		return 0
	}

	offset, convErr := strconv.ParseInt(value, 10, 64)
	if convErr != nil {
		return 0
	}

	return offset
}

func (s *statsStore) saveAggregateCursor(offset int64) error {
	_, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES('log_offset', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.FormatInt(offset, 10),
	)

	return err
}

// Apply 把一批事件累加进小时桶，并同步内存中的协议计数。
func (s *statsStore) Apply(events []rawEvent) error {
	if len(events) == 0 {
		return nil
	}

	protoCount := make(map[string]int64)
	protoLast := make(map[string]time.Time)
	sourceLast := make(map[string]time.Time)
	protoBuckets := make(map[int64]map[string]int64)
	sourceBuckets := make(map[int64]map[string]int64)

	for _, event := range events {
		at, ok := parseLogTime(event.Timestamp)
		if !ok {
			at = time.Now()
		}

		bucket := at.Unix() / 3600 * 3600
		protocol := event.EventCategory
		if protocol == "" {
			protocol = "unknown"
		}

		protoCount[protocol]++
		if at.After(protoLast[protocol]) {
			protoLast[protocol] = at
		}

		if protoBuckets[bucket] == nil {
			protoBuckets[bucket] = make(map[string]int64)
		}
		protoBuckets[bucket][protocol]++

		if event.SrcIP != "" {
			if sourceBuckets[bucket] == nil {
				sourceBuckets[bucket] = make(map[string]int64)
			}
			sourceBuckets[bucket][event.SrcIP]++

			if at.After(sourceLast[event.SrcIP]) {
				sourceLast[event.SrcIP] = at
			}
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	protoStmt, err := tx.Prepare(`INSERT INTO event_hourly(bucket, protocol, count) VALUES(?, ?, ?)
		ON CONFLICT(bucket, protocol) DO UPDATE SET count = count + excluded.count`)
	if err != nil {
		return err
	}
	defer protoStmt.Close()

	for bucket, protocols := range protoBuckets {
		for protocol, count := range protocols {
			if _, err := protoStmt.Exec(bucket, protocol, count); err != nil {
				return err
			}
		}
	}

	sourceStmt, err := tx.Prepare(`INSERT INTO source_hourly(bucket, src_ip, count, last_seen) VALUES(?, ?, ?, ?)
		ON CONFLICT(bucket, src_ip) DO UPDATE SET count = count + excluded.count,
			last_seen = MAX(last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer sourceStmt.Close()

	for bucket, items := range sourceBuckets {
		for ip, count := range items {
			lastSeen := sourceLast[ip].Unix()
			if lastSeen == 0 {
				lastSeen = bucket
			}

			if _, err := sourceStmt.Exec(bucket, ip, count, lastSeen); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for protocol, count := range protoCount {
		s.byProto[protocol] += count
		if protoLast[protocol].After(s.lastSeen[protocol]) {
			s.lastSeen[protocol] = protoLast[protocol]
		}
	}

	return nil
}

// Reset 清空历史统计：删除小时桶、重置聚合游标、同步清空内存计数。
// cursor 传当前 event.log 的文件大小，保证清空后从文件末尾继续累计，
// 不会把日志里残留的历史重新统计进来。
func (s *statsStore) Reset(cursor int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("清空统计失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		`DELETE FROM event_hourly`,
		`DELETE FROM source_hourly`,
	} {
		if _, execErr := tx.Exec(stmt); execErr != nil {
			return fmt.Errorf("清空统计失败: %w", execErr)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO meta(key, value) VALUES('log_offset', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.FormatInt(cursor, 10),
	); err != nil {
		return fmt.Errorf("重置统计游标失败: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("清空统计失败: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byProto = make(map[string]int64)
	s.lastSeen = make(map[string]time.Time)

	return nil
}

// ProtocolTotals 返回协议维度的累计事件数与最近事件时间。
func (s *statsStore) ProtocolTotals() map[string]struct {
	Count int64
	Last  time.Time
} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]struct {
		Count int64
		Last  time.Time
	}, len(s.byProto))

	for protocol, count := range s.byProto {
		out[protocol] = struct {
			Count int64
			Last  time.Time
		}{Count: count, Last: s.lastSeen[protocol]}
	}

	return out
}

func (s *statsStore) sumSince(from, to time.Time) int64 {
	query := `SELECT COALESCE(SUM(count), 0) FROM event_hourly WHERE bucket >= ?`
	args := []interface{}{from.Unix()}

	if !to.IsZero() {
		query += ` AND bucket < ?`
		args = append(args, to.Unix())
	}

	var total int64
	if err := s.db.QueryRow(query, args...).Scan(&total); err != nil {
		return 0
	}

	return total
}

func (s *statsStore) distinctSources(from, to time.Time) int64 {
	query := `SELECT COUNT(DISTINCT src_ip) FROM source_hourly WHERE bucket >= ?`
	args := []interface{}{from.Unix()}

	if !to.IsZero() {
		query += ` AND bucket < ?`
		args = append(args, to.Unix())
	}

	var total int64
	if err := s.db.QueryRow(query, args...).Scan(&total); err != nil {
		return 0
	}

	return total
}

func (s *statsStore) totalEvents() int64 {
	var total int64
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(count), 0) FROM event_hourly`).Scan(&total); err != nil {
		return 0
	}

	return total
}

// bucketSeries 返回按小时的 (count, sources) 明细，供不同粒度归并。
func (s *statsStore) bucketSeries(from time.Time) map[int64]struct{ Count, Sources int64 } {
	out := make(map[int64]struct{ Count, Sources int64 })

	rows, err := s.db.Query(`SELECT bucket, SUM(count) FROM event_hourly WHERE bucket >= ? GROUP BY bucket`, from.Unix())
	if err == nil {
		for rows.Next() {
			var bucket, count int64
			if scanErr := rows.Scan(&bucket, &count); scanErr == nil {
				item := out[bucket]
				item.Count = count
				out[bucket] = item
			}
		}
		rows.Close()
	}

	sourceRows, err := s.db.Query(
		`SELECT bucket, COUNT(DISTINCT src_ip) FROM source_hourly WHERE bucket >= ? GROUP BY bucket`,
		from.Unix(),
	)
	if err == nil {
		for sourceRows.Next() {
			var bucket, sources int64
			if scanErr := sourceRows.Scan(&bucket, &sources); scanErr == nil {
				item := out[bucket]
				item.Sources = sources
				out[bucket] = item
			}
		}
		sourceRows.Close()
	}

	return out
}

func (s *statsStore) TopSources(limit int, since time.Time) []topSource {
	if limit <= 0 || limit > 50 {
		limit = 6
	}

	rows, err := s.db.Query(
		`SELECT src_ip, SUM(count), MAX(last_seen) FROM source_hourly WHERE bucket >= ?
		 GROUP BY src_ip ORDER BY SUM(count) DESC LIMIT ?`,
		since.Unix(), limit,
	)
	if err != nil {
		return []topSource{}
	}
	defer rows.Close()

	out := make([]topSource, 0, limit)

	for rows.Next() {
		var (
			ip       string
			count    int64
			lastSeen int64
		)
		if err := rows.Scan(&ip, &count, &lastSeen); err != nil {
			continue
		}

		out = append(out, topSource{
			IP:       ip,
			Count:    count,
			LastSeen: time.Unix(lastSeen, 0).Format(time.DateTime),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })

	return out
}
