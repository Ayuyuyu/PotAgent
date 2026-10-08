package memcached

/*
Memcached 蜜罐服务（TCP 11211，文本协议）。

低交互策略：
  - 解析文本协议命令（行尾 \r\n；set/add/.../cas 后跟 <bytes> 长度的数据块）。连接级循环读取。
  - 共享内存 store 真实存储 key→(value,flags,cas,exptime)，同一实例多连接读写同一份空间，
    模拟真实 memcached 的全局缓存，get/set/gets/delete/incr/decr/touch 行为自洽。
  - 高危/写操作（set/add/replace/append/prepend/cas/delete/flush_all）照常回 STORED/DELETED/OK，
    并把 key 与上传的 value 落进事件，便于还原攻击链（payload 上传是核心情报）。
  - version / stats 返回仿真的版本与统计，增强指纹一致性。
  - 未知命令回 ERROR\r\n（宽容，避免利用工具因报错中断，命令已被事件捕获）。
*/

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"github.com/rs/xid"
)

const (
	defaultVersion = "1.6.21"
	maxValue       = 1 << 20 // 单条 value 上限 1MB，防恶意超大长度
)

// errTooLarge 表示 value 长度超过上限（已跳过消费，仅用于回 SERVER_ERROR）。
var errTooLarge = errors.New("value too large")

var (
	serviceName = "memcached"
	_           = services.Register(serviceName, MemcachedServiceInit)
	startTime   = time.Now()
)

func MemcachedServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   memcachedHandle,
		ServiceOptions: memcachedConfig{store: newMemcachedStore()},
	}
}

// memcachedConfig 协议专属配置。Version 为 VERSION 命令返回的版本号，留空回退内置 defaultVersion。
type memcachedConfig struct {
	store   *memcachedStore
	Version string `mapstructure:"version"`
}

// ---- 内存数据存储（key→value+flags+cas+exptime，支持懒过期）----

type item struct {
	value    []byte
	flags    uint32
	cas      uint64
	expireAt int64 // unix 秒；0 表示永不过期
}

type memcachedStore struct {
	mu             sync.Mutex
	data           map[string]*item
	casSeq         uint64
	statTotalItems int64
	statCmdGet     int64
	statCmdSet     int64
	statGetHits    int64
	statGetMisses  int64
}

func newMemcachedStore() *memcachedStore {
	return &memcachedStore{data: make(map[string]*item)}
}

// expireAt 将协议 exptime 转为绝对过期时间戳（0=不过期）。
func expireAtOf(exptime int64) int64 {
	if exptime <= 0 {
		return 0
	}
	now := time.Now().Unix()
	if exptime > 60*60*24*30 { // 大于 30 天视为绝对 unix 时间戳
		return exptime
	}
	return now + exptime
}

func (s *memcachedStore) cmdSet(key string, flags uint32, exptime int64, value []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.casSeq++
	s.data[key] = &item{value: value, flags: flags, cas: s.casSeq, expireAt: expireAtOf(exptime)}
	s.statTotalItems++
	s.statCmdSet++
	return "STORED\r\n"
}

func (s *memcachedStore) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[key]
	if !ok {
		return false
	}
	if it.expireAt > 0 && it.expireAt <= time.Now().Unix() {
		delete(s.data, key)
		return false
	}
	return true
}

func (s *memcachedStore) cmdAdd(key string, flags uint32, exptime int64, value []byte) string {
	if s.has(key) {
		return "NOT_STORED\r\n"
	}
	s.cmdSet(key, flags, exptime, value)
	return "STORED\r\n"
}

func (s *memcachedStore) cmdReplace(key string, flags uint32, exptime int64, value []byte) string {
	if !s.has(key) {
		return "NOT_STORED\r\n"
	}
	s.cmdSet(key, flags, exptime, value)
	return "STORED\r\n"
}

func (s *memcachedStore) cmdAppend(key string, value []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := s.data[key]
	if it == nil || (it.expireAt > 0 && it.expireAt <= time.Now().Unix()) {
		return "NOT_STORED\r\n"
	}
	it.value = append(it.value, value...)
	s.casSeq++
	it.cas = s.casSeq
	return "STORED\r\n"
}

func (s *memcachedStore) cmdPrepend(key string, value []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := s.data[key]
	if it == nil || (it.expireAt > 0 && it.expireAt <= time.Now().Unix()) {
		return "NOT_STORED\r\n"
	}
	it.value = append(append([]byte{}, value...), it.value...)
	s.casSeq++
	it.cas = s.casSeq
	return "STORED\r\n"
}

func (s *memcachedStore) cmdCas(key string, flags uint32, exptime int64, value []byte, casTok uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[key]
	if !ok {
		return "NOT_FOUND\r\n"
	}
	if it.expireAt > 0 && it.expireAt <= time.Now().Unix() {
		delete(s.data, key)
		return "NOT_FOUND\r\n"
	}
	if it.cas != casTok {
		return "EXISTS\r\n"
	}
	s.casSeq++
	s.data[key] = &item{value: value, flags: flags, cas: s.casSeq, expireAt: expireAtOf(exptime)}
	s.statTotalItems++
	return "STORED\r\n"
}

func (s *memcachedStore) cmdDelete(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key]; !ok {
		return "NOT_FOUND\r\n"
	}
	delete(s.data, key)
	return "DELETED\r\n"
}

func (s *memcachedStore) cmdTouch(key string, exptime int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[key]
	if !ok {
		return "NOT_FOUND\r\n"
	}
	if it.expireAt > 0 && it.expireAt <= time.Now().Unix() {
		delete(s.data, key)
		return "NOT_FOUND\r\n"
	}
	it.expireAt = expireAtOf(exptime)
	return "TOUCHED\r\n"
}

func (s *memcachedStore) cmdIncrDecr(key, delta string, decr bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[key]
	if !ok {
		return "NOT_FOUND\r\n"
	}
	if it.expireAt > 0 && it.expireAt <= time.Now().Unix() {
		delete(s.data, key)
		return "NOT_FOUND\r\n"
	}
	cur, err := strconv.ParseInt(string(it.value), 10, 64)
	if err != nil {
		return "CLIENT_ERROR cannot increment or decrement non-numeric value\r\n"
	}
	d, err := strconv.ParseInt(delta, 10, 64)
	if err != nil || d < 0 {
		return "CLIENT_ERROR invalid increment value\r\n"
	}
	if decr {
		cur -= d
		if cur < 0 {
			cur = 0
		}
	} else {
		cur += d
	}
	it.value = []byte(strconv.FormatInt(cur, 10))
	s.casSeq++
	it.cas = s.casSeq
	return strconv.FormatInt(cur, 10) + "\r\n"
}

func (s *memcachedStore) cmdFlush() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]*item)
	return "OK\r\n"
}

// getMulti 返回 get/gets 的完整响应（VALUE 块 + END）。调用方应保证 keys 非空。
func (s *memcachedStore) getMulti(keys []string, withCas bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, k := range keys {
		it, ok := s.data[k]
		if !ok {
			s.statGetMisses++
			s.statCmdGet++
			continue
		}
		if it.expireAt > 0 && it.expireAt <= time.Now().Unix() {
			delete(s.data, k)
			s.statGetMisses++
			s.statCmdGet++
			continue
		}
		s.statGetHits++
		s.statCmdGet++
		b.WriteString("VALUE ")
		b.WriteString(k)
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(uint64(it.flags), 10))
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(len(it.value)))
		if withCas {
			b.WriteByte(' ')
			b.WriteString(strconv.FormatUint(it.cas, 10))
		}
		b.WriteString("\r\n")
		b.Write(it.value)
		b.WriteString("\r\n")
	}
	b.WriteString("END\r\n")
	return b.String()
}

// statsString 返回 stats 命令的仿真统计响应。
func (s *memcachedStore) statsString(version string) string {
	s.mu.Lock()
	n := len(s.data)
	var bytes int64
	for _, it := range s.data {
		bytes += int64(len(it.value))
	}
	st := s.statTotalItems
	cg, cs, gh, gm := s.statCmdGet, s.statCmdSet, s.statGetHits, s.statGetMisses
	s.mu.Unlock()
	now := time.Now().Unix()
	uptime := int(time.Since(startTime).Seconds())
	var b strings.Builder
	b.WriteString("STAT pid 1\r\n")
	b.WriteString("STAT uptime " + strconv.Itoa(uptime) + "\r\n")
	b.WriteString("STAT time " + strconv.FormatInt(now, 10) + "\r\n")
	b.WriteString("STAT version " + version + "\r\n")
	b.WriteString("STAT libevent 2.1.8-stable\r\n")
	b.WriteString("STAT pointer_size 64\r\n")
	b.WriteString("STAT curr_items " + strconv.Itoa(n) + "\r\n")
	b.WriteString("STAT total_items " + strconv.FormatInt(st, 10) + "\r\n")
	b.WriteString("STAT bytes " + strconv.FormatInt(bytes, 10) + "\r\n")
	b.WriteString("STAT curr_connections 1\r\n")
	b.WriteString("STAT total_connections 1\r\n")
	b.WriteString("STAT cmd_get " + strconv.FormatInt(cg, 10) + "\r\n")
	b.WriteString("STAT cmd_set " + strconv.FormatInt(cs, 10) + "\r\n")
	b.WriteString("STAT cmd_flush 0\r\n")
	b.WriteString("STAT get_hits " + strconv.FormatInt(gh, 10) + "\r\n")
	b.WriteString("STAT get_misses " + strconv.FormatInt(gm, 10) + "\r\n")
	b.WriteString("STAT limit_maxbytes 67108864\r\n")
	b.WriteString("STAT threads 4\r\n")
	b.WriteString("END\r\n")
	return b.String()
}

func versionString(version string) string {
	return "VERSION " + version + "\r\n"
}

// ---- 协议读取 ----

func readLine(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// readDataBlock 读取存储命令后的 <n> 字节 value + 结尾 \r\n。
// n 超过上限时丢弃多余字节（保持流对齐）并返回 errTooLarge。
func readDataBlock(r *bufio.Reader, n int64) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative length")
	}
	if n > maxValue {
		buf := make([]byte, 4096)
		remaining := n + 2
		for remaining > 0 {
			to := remaining
			if to > int64(len(buf)) {
				to = int64(len(buf))
			}
			rn, err := r.Read(buf[:to])
			if rn > 0 {
				remaining -= int64(rn)
			}
			if err != nil {
				return nil, err
			}
		}
		return nil, errTooLarge
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func isStorage(cmd string) bool {
	switch cmd {
	case "SET", "ADD", "REPLACE", "APPEND", "PREPEND", "CAS":
		return true
	}
	return false
}

// parseStorage 解析存储命令参数；ok=false 表示命令格式不足（行级格式错误）。
func parseStorage(fields []string, cmd string) (key string, flags uint32, exptime int64, n int64,
	noreply bool, casTok uint64, ok bool) {
	if cmd == "CAS" {
		if len(fields) < 6 {
			return "", 0, 0, 0, false, 0, false
		}
		key = fields[1]
		flags = atoU32(fields[2])
		exptime = atoI64(fields[3])
		n = atoI64(fields[4])
		casTok = atoU64(fields[5])
		noreply = len(fields) >= 7 && strings.EqualFold(fields[6], "noreply")
	} else {
		if len(fields) < 5 {
			return "", 0, 0, 0, false, 0, false
		}
		key = fields[1]
		flags = atoU32(fields[2])
		exptime = atoI64(fields[3])
		n = atoI64(fields[4])
		noreply = len(fields) >= 6 && strings.EqualFold(fields[5], "noreply")
	}
	return key, flags, exptime, n, noreply, casTok, true
}

func atoU32(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}

func atoI64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func atoU64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// ---- 连接处理 ----

func memcachedHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Info(baseOptions.Application, " listen on ", address)

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleServiceConn(&conn, service)
		}
	}
}

func handleServiceConn(conn *net.Conn, service *services.Service) {
	defer (*conn).Close()
	id := xid.New()
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(memcachedConfig)
	store := cfg.store
	version := cfg.Version
	if version == "" {
		version = defaultVersion
	}

	srcAddr, err := common.GetConnSrcIPAndSrcPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "memcached-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":             baseOptions.Protocol,
		"application":          baseOptions.Application,
		"memcached.session-id": id.String(),
	}))

	pushClose := func() {
		event.EventPush(event.NewEvent(serviceName, "memcached-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":             baseOptions.Protocol,
			"application":          baseOptions.Application,
			"memcached.session-id": id.String(),
		}))
	}

	writeReply := func(s string) {
		if _, err := (*conn).Write([]byte(s)); err != nil {
			logger.Log.Debug("memcached write error:", err)
		}
	}

	reader := bufio.NewReader(*conn)
	for {
		line, err := readLine(reader)
		if err != nil {
			if err != io.EOF {
				logger.Log.Debug("memcached read error:", err)
			}
			pushClose()
			return
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		cmd := strings.ToUpper(fields[0])

		details := map[string]interface{}{
			"protocol":             baseOptions.Protocol,
			"application":          baseOptions.Application,
			"memcached.session-id": id.String(),
			"memcached.command":    cmd,
			"memcached.args":       fields,
		}
		if len(fields) >= 2 {
			details["memcached.key"] = fields[1]
		}

		if isStorage(cmd) {
			key, flags, exptime, n, noreply, casTok, ok := parseStorage(fields, cmd)
			if !ok {
				writeReply("CLIENT_ERROR bad command line format\r\n")
				event.EventPush(event.NewEvent(serviceName, "memcached-command", srcAddr, dstAddr, details))
				continue
			}
			data, derr := readDataBlock(reader, n)
			if derr != nil {
				if derr == errTooLarge {
					if !noreply {
						writeReply("SERVER_ERROR object too large for cache\r\n")
					}
					event.EventPush(event.NewEvent(serviceName, "memcached-command", srcAddr, dstAddr, details))
					continue
				}
				pushClose()
				return
			}
			details["memcached.data"] = string(data)
			details["memcached.data_size"] = len(data)
			details["memcached.flags"] = flags
			details["memcached.bytes"] = n
			details["memcached.exptime"] = exptime
			details["memcached.noreply"] = noreply

			var reply string
			switch cmd {
			case "SET":
				reply = store.cmdSet(key, flags, exptime, data)
			case "ADD":
				reply = store.cmdAdd(key, flags, exptime, data)
			case "REPLACE":
				reply = store.cmdReplace(key, flags, exptime, data)
			case "APPEND":
				reply = store.cmdAppend(key, data)
			case "PREPEND":
				reply = store.cmdPrepend(key, data)
			case "CAS":
				details["memcached.cas_unique"] = casTok
				reply = store.cmdCas(key, flags, exptime, data, casTok)
			}
			if !noreply {
				writeReply(reply)
			}
			event.EventPush(event.NewEvent(serviceName, "memcached-command", srcAddr, dstAddr, details))
			continue
		}

		// 非存储命令
		reply, closeConn := handleNonStorage(store, cmd, fields, version)
		event.EventPush(event.NewEvent(serviceName, "memcached-command", srcAddr, dstAddr, details))
		if reply != "" {
			writeReply(reply)
		}
		if closeConn {
			pushClose()
			return
		}
	}
}

// handleNonStorage 处理非存储类命令，返回响应（可能为空）与是否关闭连接。
func handleNonStorage(store *memcachedStore, cmd string, fields []string, version string) (string, bool) {
	switch cmd {
	case "GET", "GETS":
		if len(fields) < 2 {
			return "CLIENT_ERROR bad command line format\r\n", false
		}
		return store.getMulti(fields[1:], cmd == "GETS"), false
	case "DELETE":
		if len(fields) < 2 {
			return "CLIENT_ERROR bad command line format\r\n", false
		}
		noreply := len(fields) >= 3 && strings.EqualFold(fields[2], "noreply")
		reply := store.cmdDelete(fields[1])
		if noreply {
			return "", false
		}
		return reply, false
	case "INCR", "DECR":
		if len(fields) < 3 {
			return "CLIENT_ERROR bad command line format\r\n", false
		}
		noreply := len(fields) >= 4 && strings.EqualFold(fields[3], "noreply")
		reply := store.cmdIncrDecr(fields[1], fields[2], cmd == "DECR")
		if noreply {
			return "", false
		}
		return reply, false
	case "TOUCH":
		if len(fields) < 3 {
			return "CLIENT_ERROR bad command line format\r\n", false
		}
		noreply := len(fields) >= 4 && strings.EqualFold(fields[3], "noreply")
		reply := store.cmdTouch(fields[1], atoI64(fields[2]))
		if noreply {
			return "", false
		}
		return reply, false
	case "FLUSH_ALL":
		noreply := len(fields) >= 2 && strings.EqualFold(fields[len(fields)-1], "noreply")
		store.cmdFlush()
		if noreply {
			return "", false
		}
		return "OK\r\n", false
	case "VERSION":
		return versionString(version), false
	case "STATS":
		return store.statsString(version), false
	case "QUIT":
		return "", true
	default:
		return "ERROR\r\n", false
	}
}
