package server

import (
	"bufio"
	"encoding/json"
	"hash/fnv"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rawEvent 对应 event.log 的一行（snake_case，来自 event/event.go）。
type rawEvent struct {
	Timestamp     string                 `json:"timestamp"`
	EventCategory string                 `json:"event_category"`
	EventType     string                 `json:"event_type"`
	SrcIP         string                 `json:"src_ip"`
	DstIP         string                 `json:"dst_ip"`
	IPProtocol    string                 `json:"ip_protocol"`
	SrcPort       uint16                 `json:"src_port"`
	DstPort       uint16                 `json:"dst_port"`
	Details       map[string]interface{} `json:"details"`
}

type logQuery struct {
	keyword  string
	protocol string
	srcIP    string
	rangeKey string
}

func (q logQuery) cutoff() time.Time {
	switch q.rangeKey {
	case "5m":
		return time.Now().Add(-5 * time.Minute)
	case "1h":
		return time.Now().Add(-time.Hour)
	case "24h":
		return time.Now().Add(-24 * time.Hour)
	default:
		return time.Time{}
	}
}

func (q logQuery) match(entry logEntry, raw string) bool {
	if q.protocol != "" && entry.EventCategory != q.protocol {
		return false
	}

	if q.srcIP != "" && !strings.HasPrefix(entry.SrcIP, q.srcIP) {
		return false
	}

	if cutoff := q.cutoff(); !cutoff.IsZero() {
		at, ok := parseLogTime(entry.Timestamp)
		if !ok || at.Before(cutoff) {
			return false
		}
	}

	if q.keyword != "" && !strings.Contains(strings.ToLower(raw), strings.ToLower(q.keyword)) {
		return false
	}

	return true
}

func parseLogTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}

	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
		if at, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return at, true
		}
	}

	return time.Time{}, false
}

func entryID(line string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(line))

	return strconv.FormatUint(hasher.Sum64(), 36)
}

// lineID 用行在文件中的起始偏移作为记录 ID。
// 不能只用行内容哈希：同一秒内两条完全相同的事件会得到同一个 ID，
// 前端 v-for 的 key 重复会让列表行错乱跳动。
func lineID(offset int64) string {
	return "L" + strconv.FormatInt(offset, 36)
}

func toEntry(line string, fallbackID string) (logEntry, string, bool) {
	trimmed := strings.TrimSpace(line)

	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return logEntry{}, trimmed, false
	}

	var raw rawEvent
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return logEntry{}, trimmed, false
	}

	id := fallbackID
	if id == "" {
		id = entryID(trimmed)
	}

	return logEntry{
		ID:            id,
		Timestamp:     raw.Timestamp,
		EventCategory: raw.EventCategory,
		EventType:     raw.EventType,
		SrcIP:         raw.SrcIP,
		DstIP:         raw.DstIP,
		IPProtocol:    raw.IPProtocol,
		SrcPort:       raw.SrcPort,
		DstPort:       raw.DstPort,
		Details:       raw.Details,
	}, trimmed, true
}

// logReader 读取 event.log。文件为单文件追加、无轮转，游标即字节偏移。
type logReader struct {
	path string
	mu   sync.Mutex
}

func newLogReader(path string) *logReader {
	return &logReader{path: path}
}

func (r *logReader) size() int64 {
	info, err := os.Stat(r.path)
	if err != nil {
		return 0
	}

	return info.Size()
}

// ModTime 返回日志最后写入时间，供概览展示。
func (r *logReader) ModTime() time.Time {
	info, err := os.Stat(r.path)
	if err != nil {
		return time.Time{}
	}

	return info.ModTime()
}

// Tail 增量读取，返回值按时间倒序（最新一条在最前），与前端"最新在最上"一致。
//
// cursor 为 0（首次加载）或已越过文件末尾（日志被截断/轮转）时，直接从文件尾部
// 倒读最新的 limit 条，避免像以前那样从文件开头一路追赶历史数据。
func (r *logReader) Tail(query logQuery, cursor int64, limit int) (logTailResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return logTailResult{Entries: []logEntry{}, Cursor: "0"}, nil
		}

		return logTailResult{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return logTailResult{}, err
	}

	fileSize := info.Size()

	if cursor <= 0 || cursor > fileSize {
		entries := scanBackward(file, fileSize, query, limit)

		return logTailResult{
			Entries:     entries,
			Cursor:      strconv.FormatInt(fileSize, 10),
			Truncated:   cursor > fileSize,
			LogFileSize: fileSize,
			Matched:     len(entries),
		}, nil
	}

	if _, err := file.Seek(cursor, io.SeekStart); err != nil {
		return logTailResult{}, err
	}

	reader := bufio.NewReaderSize(file, 128*1024)
	offset := cursor
	entries := make([]logEntry, 0, limit)
	scanned := 0

	for len(entries) < limit && scanned < 4000 {
		lineStart := offset
		line, readErr := reader.ReadString('\n')

		if len(line) > 0 {
			offset += int64(len(line))
			scanned++

			if entry, raw, ok := toEntry(line, lineID(lineStart)); ok && query.match(entry, raw) {
				entries = append(entries, entry)
			}
		}

		if readErr != nil {
			break
		}
	}

	// 文件内是顺序追加，倒转后即为"最新在前"
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	return logTailResult{
		Entries:     entries,
		Cursor:      strconv.FormatInt(offset, 10),
		Truncated:   false,
		LogFileSize: fileSize,
		Matched:     len(entries),
	}, nil
}

// scanBackward 从文件尾部倒读，返回最新的 limit 条匹配记录（最新在前）。
// 所有扫描路径共用同一份行偏移，保证同一条日志的 ID 稳定。
func scanBackward(file *os.File, fileSize int64, query logQuery, limit int) []logEntry {
	const (
		chunkSize = 64 * 1024
		maxScan   = 8 * 1024 * 1024
	)

	offset := fileSize
	scanned := 0
	entries := make([]logEntry, 0, limit)
	var pending []byte

	for offset > 0 && len(entries) < limit && scanned < maxScan {
		readSize := int64(chunkSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize
		scanned += int(readSize)

		buf := make([]byte, readSize)
		if _, readErr := file.ReadAt(buf, offset); readErr != nil && readErr != io.EOF {
			break
		}

		chunk := make([]byte, 0, len(buf)+len(pending))
		chunk = append(chunk, buf...)
		chunk = append(chunk, pending...)

		lines := strings.Split(string(chunk), "\n")

		// 每行在文件中的起始偏移，用于生成稳定且唯一的 ID
		starts := make([]int64, len(lines))
		cursor := offset
		for i, line := range lines {
			starts[i] = cursor
			cursor += int64(len(line)) + 1
		}

		if offset > 0 {
			pending = []byte(lines[0])
			lines = lines[1:]
			starts = starts[1:]
		} else {
			pending = nil
		}

		for i := len(lines) - 1; i >= 0; i-- {
			if entry, raw, ok := toEntry(lines[i], lineID(starts[i])); ok && query.match(entry, raw) {
				entries = append(entries, entry)
				if len(entries) >= limit {
					break
				}
			}
		}
	}

	return entries
}

// Search 从文件尾部倒读到头部（最多 8MB），返回最新的 limit 条匹配记录（最新在前）。
func (r *logReader) Search(query logQuery, limit int) (logTailResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return logTailResult{Entries: []logEntry{}, Cursor: "0"}, nil
		}

		return logTailResult{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return logTailResult{}, err
	}

	fileSize := info.Size()
	entries := scanBackward(file, fileSize, query, limit)

	return logTailResult{
		Entries:     entries,
		Cursor:      strconv.FormatInt(fileSize, 10),
		Truncated:   false,
		LogFileSize: fileSize,
		Matched:     len(entries),
	}, nil
}

// ReadFrom 供统计聚合使用：从 offset 读取完整行，最多 maxBytes 字节。
// 不完整的尾行不会被消费，避免统计到半条记录。
func (r *logReader) ReadFrom(offset int64, maxBytes int64) ([]rawEvent, int64, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, offset, false, nil
		}

		return nil, offset, false, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, offset, false, err
	}

	fileSize := info.Size()
	truncated := false

	if offset > fileSize {
		offset = 0
		truncated = true
	}

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, truncated, err
	}

	reader := bufio.NewReaderSize(file, 128*1024)
	advance := int64(0)
	events := make([]rawEvent, 0, 256)

	for advance < maxBytes {
		line, readErr := reader.ReadString('\n')

		if !strings.HasSuffix(line, "\n") {
			break
		}

		advance += int64(len(line))

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{") {
			var parsed rawEvent
			if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
				events = append(events, parsed)
			}
		}

		if readErr != nil {
			break
		}
	}

	return events, offset + advance, truncated, nil
}
