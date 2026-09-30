package redis

/*
Redis 蜜罐服务（TCP 6379，RESP 协议）。

低交互策略：
  - 解析 RESP 多 bulk 命令数组（*N\r\n$len\r\narg\r\n...）与内联命令，连接级循环读取。
  - 内存 store 为「多类型真存真取」：string / hash / list / set / zset 均真实存储，
    支持 TTL 懒过期。这让 redis-cli / 扫描器 / 利用脚本看到的是一份自洽的、可反复读写的数据，
    比纯占位 +OK 更难被识别为蜜罐。
  - 对无法真实模拟的命令（位图、GEO、HyperLogLog、发布订阅、脚本等）仍回 +OK，
    并把命令原样落进事件，便于还原攻击链。
  - AUTH 永远成功（不校验口令，全捕获为情报）；CONFIG SET / SLAVEOF / MODULE LOAD 等
    高危操作照常回 +OK 并把参数落进事件。
  - 未知命令也回 +OK（宽容，避免利用工具因报错而中断，命令本身已被事件捕获）。
*/

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"sort"
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

var (
	serviceName = "redis"
	_           = services.Register(serviceName, RedisServiceInit)
)

// maxBulk 限制单条 bulk 字符串长度，防止恶意超大长度导致内存爆炸
const maxBulk = 1 << 24 // 16MB

func RedisServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   redisHandle,
		ServiceOptions: redisConfig{store: newRedisStore()},
	}
	return s
}

// redisConfig 协议专属配置。
// store 为该服务实例共享的内存数据（同一实例的多连接读写同一份，模拟真实 redis 的全局空间）。
// fakeInfo 为 INFO 命令返回的伪信息；yaml 未配置或为空时回退到内置 fakeRedisInfo 常量。
type redisConfig struct {
	store    *redisStore
	FakeInfo string `mapstructure:"fake_info"`
}

// resolveFakeInfo 返回 INFO 命令的伪信息；未配置或为空时回退到内置 fakeRedisInfo 常量。
func resolveFakeInfo(cfg redisConfig) string {
	if cfg.FakeInfo == "" {
		return fakeRedisInfo
	}
	return cfg.FakeInfo
}

// ---- 内存数据存储（多类型：string/hash/list/set/zset，支持 TTL 懒过期）----

type redisType byte

const (
	typeNone   redisType = 0
	typeString redisType = iota + 1
	typeHash
	typeList
	typeSet
	typeZSet
)

type zmember struct {
	score  float64
	member string
}

type redisObject struct {
	typ    redisType
	expire int64 // unix 毫秒；0 表示永不过期
	str    string
	hash   map[string]string
	list   []string
	set    map[string]struct{}
	zset   []zmember
}

type redisStore struct {
	mu   sync.Mutex
	data map[string]*redisObject
}

func newRedisStore() *redisStore {
	return &redisStore{data: make(map[string]*redisObject)}
}

func (s *redisStore) nowMs() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }

// touchUnlocked 返回 key 对应的对象（假定调用方已加锁）；若已过期则删除并返回 false。
func (s *redisStore) touchUnlocked(key string) (*redisObject, bool) {
	o, ok := s.data[key]
	if !ok {
		return nil, false
	}
	if o.expire > 0 && o.expire <= s.nowMs() {
		delete(s.data, key)
		return nil, false
	}
	return o, true
}

// ensureUnlocked 取或新建指定类型的对象（假定调用方已加锁）。类型冲突时返回 nil。
func (s *redisStore) ensureUnlocked(key string, typ redisType) *redisObject {
	if o, ok := s.touchUnlocked(key); ok {
		if o.typ == typ {
			return o
		}
		return nil
	}
	o := &redisObject{typ: typ}
	if typ == typeHash {
		o.hash = make(map[string]string)
	}
	if typ == typeSet {
		o.set = make(map[string]struct{})
	}
	s.data[key] = o
	return o
}

// ---- 字符串类型（SET 会覆盖任意既有类型，与真实 redis 一致）----

func (s *redisStore) getStrUnlocked(key string) (string, bool) {
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeString {
		return "", false
	}
	return o.str, true
}

func (s *redisStore) setStrUnlocked(key, val string, expireMs int64) {
	s.data[key] = &redisObject{typ: typeString, str: val, expire: expireMs}
}

func (s *redisStore) getString(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getStrUnlocked(key)
}

func (s *redisStore) setStr(key, val string, expireMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setStrUnlocked(key, val, expireMs)
}

func (s *redisStore) incr(key string, delta int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.getStrUnlocked(key)
	cur := int64(0)
	if ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cur = n
		}
	}
	cur += delta
	s.setStrUnlocked(key, strconv.FormatInt(cur, 10), 0)
	return cur
}

func (s *redisStore) appendStr(key, val string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _ := s.getStrUnlocked(key)
	v += val
	s.setStrUnlocked(key, v, 0)
	return len(v)
}

func (s *redisStore) strlen(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.getStrUnlocked(key)
	if !ok {
		return 0
	}
	return len(v)
}

func (s *redisStore) mset(pairs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i+1 < len(pairs); i += 2 {
		s.setStrUnlocked(pairs[i], pairs[i+1], 0)
	}
}

func (s *redisStore) mget(keys []string) []*string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*string, 0, len(keys))
	for _, k := range keys {
		if v, ok := s.getStrUnlocked(k); ok {
			out = append(out, &v)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (s *redisStore) getset(key, val string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.getStrUnlocked(key)
	s.setStrUnlocked(key, val, 0)
	return old, ok
}

func (s *redisStore) setnx(key, val string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.touchUnlocked(key); ok {
		return false
	}
	s.setStrUnlocked(key, val, 0)
	return true
}

// ---- 通用 key 操作 ----

func (s *redisStore) del(keys []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, k := range keys {
		if _, ok := s.touchUnlocked(k); ok {
			delete(s.data, k)
			n++
		}
	}
	return n
}

func (s *redisStore) exists(keys []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, k := range keys {
		if _, ok := s.touchUnlocked(k); ok {
			n++
		}
	}
	return n
}

// ttl 返回剩余秒：-2 不存在，-1 永不过期，否则剩余秒。
func (s *redisStore) ttl(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok {
		return -2
	}
	if o.expire == 0 {
		return -1
	}
	rem := o.expire - s.nowMs()
	if rem <= 0 {
		return -2
	}
	return rem / 1000
}

func (s *redisStore) pttl(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok {
		return -2
	}
	if o.expire == 0 {
		return -1
	}
	rem := o.expire - s.nowMs()
	if rem <= 0 {
		return -2
	}
	return rem
}

func (s *redisStore) expire(key string, ms int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok {
		return false
	}
	o.expire = s.nowMs() + ms
	return true
}

func (s *redisStore) persist(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok {
		return false
	}
	o.expire = 0
	return true
}

func (s *redisStore) rename(src, dst string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(src)
	if !ok {
		return false
	}
	s.data[dst] = o
	delete(s.data, src)
	return true
}

// keys 按 glob 模式（支持 * 与 ?）返回匹配的键。
func (s *redisStore) keys(pattern string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	re := globToRegexp(pattern)
	now := s.nowMs()
	var out []string
	for k, o := range s.data {
		if o.expire > 0 && o.expire <= now {
			continue
		}
		if re.MatchString(k) {
			out = append(out, k)
		}
	}
	return out
}

// scan 实现简单的游标遍历：收集全部匹配键排序后按 count 分页。
// 返回 (下一游标字符串, 本页键)。游标走完返回 "0"。
func (s *redisStore) scan(cursorStr, pattern string, count int) (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count <= 0 {
		count = 10
	}
	re := globToRegexp(pattern)
	now := s.nowMs()
	var all []string
	for k, o := range s.data {
		if o.expire > 0 && o.expire <= now {
			continue
		}
		if re.MatchString(k) {
			all = append(all, k)
		}
	}
	sort.Strings(all)
	cur, err := strconv.Atoi(cursorStr)
	if err != nil || cur < 0 {
		cur = 0
	}
	end := cur + count
	if end > len(all) {
		end = len(all)
	}
	page := all[cur:end]
	next := "0"
	if end < len(all) {
		next = strconv.Itoa(end)
	}
	return next, page
}

// typeName 返回 key 的类型名（与 redis TYPE 一致）。
func (s *redisStore) typeName(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok {
		return "none"
	}
	switch o.typ {
	case typeString:
		return "string"
	case typeHash:
		return "hash"
	case typeList:
		return "list"
	case typeSet:
		return "set"
	case typeZSet:
		return "zset"
	}
	return "none"
}

// typeOf 返回 key 的类型（缺失为 typeNone），用于 WRONGTYPE 检测。
func (s *redisStore) typeOf(key string) redisType {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok {
		return typeNone
	}
	return o.typ
}

// isWrongType 报告 key 存在但类型不是 want（应回 WRONGTYPE 错误）。
func (s *redisStore) isWrongType(key string, want redisType) bool {
	t := s.typeOf(key)
	return t != typeNone && t != want
}

func (s *redisStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

func (s *redisStore) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]*redisObject)
}

// ---- 哈希类型 ----

func (s *redisStore) hset(key string, fields []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeHash)
	if o == nil {
		return -1
	}
	var added int64
	for i := 0; i+1 < len(fields); i += 2 {
		f, v := fields[i], fields[i+1]
		if _, ok := o.hash[f]; !ok {
			added++
		}
		o.hash[f] = v
	}
	return added
}

func (s *redisStore) hget(key, field string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return "", false
	}
	v, ok2 := o.hash[field]
	return v, ok2
}

func (s *redisStore) hgetAll(key string) ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return nil, nil
	}
	fields := make([]string, 0, len(o.hash))
	values := make([]string, 0, len(o.hash))
	for f, v := range o.hash {
		fields = append(fields, f)
		values = append(values, v)
	}
	return fields, values
}

func (s *redisStore) hmget(key string, fields []string) []*string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return nil
	}
	out := make([]*string, 0, len(fields))
	for _, f := range fields {
		if v, ok2 := o.hash[f]; ok2 {
			out = append(out, &v)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (s *redisStore) hdel(key string, fields []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return 0
	}
	var n int64
	for _, f := range fields {
		if _, ok2 := o.hash[f]; ok2 {
			delete(o.hash, f)
			n++
		}
	}
	if len(o.hash) == 0 {
		delete(s.data, key)
	}
	return n
}

func (s *redisStore) hlen(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return 0
	}
	return int64(len(o.hash))
}

func (s *redisStore) hkeys(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return nil
	}
	out := make([]string, 0, len(o.hash))
	for f := range o.hash {
		out = append(out, f)
	}
	return out
}

func (s *redisStore) hvals(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeHash {
		return nil
	}
	out := make([]string, 0, len(o.hash))
	for _, v := range o.hash {
		out = append(out, v)
	}
	return out
}

func (s *redisStore) hincrby(key, field string, delta int64) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeHash)
	if o == nil {
		return 0, false
	}
	cur, err := strconv.ParseInt(o.hash[field], 10, 64)
	if err != nil {
		cur = 0
	}
	cur += delta
	o.hash[field] = strconv.FormatInt(cur, 10)
	return cur, true
}

// ---- 列表类型（index 0 为表头）----

func (s *redisStore) lpush(key string, vals []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeList)
	if o == nil {
		return -1
	}
	for _, v := range vals {
		o.list = append([]string{v}, o.list...)
	}
	return int64(len(o.list))
}

func (s *redisStore) rpush(key string, vals []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeList)
	if o == nil {
		return -1
	}
	o.list = append(o.list, vals...)
	return int64(len(o.list))
}

func (s *redisStore) lrange(key string, start, stop int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeList {
		return nil
	}
	n := len(o.list)
	if n == 0 {
		return []string{}
	}
	lo, hi := normRange(start, stop, n)
	if lo > hi {
		return []string{}
	}
	out := make([]string, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		out = append(out, o.list[i])
	}
	return out
}

func (s *redisStore) llen(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeList {
		return 0
	}
	return int64(len(o.list))
}

func (s *redisStore) lpop(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeList || len(o.list) == 0 {
		return "", false
	}
	v := o.list[0]
	o.list = o.list[1:]
	if len(o.list) == 0 {
		delete(s.data, key)
	}
	return v, true
}

func (s *redisStore) rpop(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeList || len(o.list) == 0 {
		return "", false
	}
	idx := len(o.list) - 1
	v := o.list[idx]
	o.list = o.list[:idx]
	if len(o.list) == 0 {
		delete(s.data, key)
	}
	return v, true
}

// ---- 集合类型 ----

func (s *redisStore) sadd(key string, members []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeSet)
	if o == nil {
		return -1
	}
	var added int64
	for _, m := range members {
		if _, ok := o.set[m]; !ok {
			o.set[m] = struct{}{}
			added++
		}
	}
	return added
}

func (s *redisStore) srem(key string, members []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeSet {
		return 0
	}
	var n int64
	for _, m := range members {
		if _, ok2 := o.set[m]; ok2 {
			delete(o.set, m)
			n++
		}
	}
	if len(o.set) == 0 {
		delete(s.data, key)
	}
	return n
}

func (s *redisStore) smembers(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeSet {
		return []string{}
	}
	out := make([]string, 0, len(o.set))
	for m := range o.set {
		out = append(out, m)
	}
	return out
}

func (s *redisStore) sismember(key, member string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeSet {
		return false
	}
	_, ok2 := o.set[member]
	return ok2
}

func (s *redisStore) scard(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeSet {
		return 0
	}
	return int64(len(o.set))
}

func (s *redisStore) sinter(keys []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result map[string]struct{}
	for i, k := range keys {
		o, ok := s.touchUnlocked(k)
		if !ok || o.typ != typeSet {
			return []string{}
		}
		if i == 0 {
			result = make(map[string]struct{}, len(o.set))
			for m := range o.set {
				result[m] = struct{}{}
			}
		} else {
			for m := range result {
				if _, ok2 := o.set[m]; !ok2 {
					delete(result, m)
				}
			}
		}
	}
	out := make([]string, 0, len(result))
	for m := range result {
		out = append(out, m)
	}
	return out
}

func (s *redisStore) sunion(keys []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]struct{})
	for _, k := range keys {
		o, ok := s.touchUnlocked(k)
		if !ok || o.typ != typeSet {
			continue
		}
		for m := range o.set {
			result[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(result))
	for m := range result {
		out = append(out, m)
	}
	return out
}

func (s *redisStore) sdiff(keys []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(keys) == 0 {
		return []string{}
	}
	o, ok := s.touchUnlocked(keys[0])
	if !ok || o.typ != typeSet {
		return []string{}
	}
	result := make(map[string]struct{}, len(o.set))
	for m := range o.set {
		result[m] = struct{}{}
	}
	for _, k := range keys[1:] {
		o2, ok2 := s.touchUnlocked(k)
		if !ok2 || o2.typ != typeSet {
			continue
		}
		for m := range o2.set {
			delete(result, m)
		}
	}
	out := make([]string, 0, len(result))
	for m := range result {
		out = append(out, m)
	}
	return out
}

// ---- 有序集合类型 ----

func (s *redisStore) zadd(key string, elems []zmember) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeZSet)
	if o == nil {
		return 0, true
	}
	var added int64
	for _, e := range elems {
		found := false
		for i := range o.zset {
			if o.zset[i].member == e.member {
				o.zset[i].score = e.score
				found = true
				break
			}
		}
		if !found {
			o.zset = append(o.zset, e)
			added++
		}
	}
	return added, false
}

func (s *redisStore) zrange(key string, start, stop int) []zmember {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeZSet {
		return nil
	}
	sorted := append([]zmember(nil), o.zset...)
	sortZSet(sorted)
	n := len(sorted)
	if n == 0 {
		return []zmember{}
	}
	lo, hi := normRange(start, stop, n)
	if lo > hi {
		return []zmember{}
	}
	return append([]zmember(nil), sorted[lo:hi+1]...)
}

func (s *redisStore) zcard(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeZSet {
		return 0
	}
	return int64(len(o.zset))
}

func (s *redisStore) zscore(key, member string) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeZSet {
		return 0, false
	}
	for _, m := range o.zset {
		if m.member == member {
			return m.score, true
		}
	}
	return 0, false
}

func (s *redisStore) zrank(key, member string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeZSet {
		return 0, false
	}
	sorted := append([]zmember(nil), o.zset...)
	sortZSet(sorted)
	for i, m := range sorted {
		if m.member == member {
			return int64(i), true
		}
	}
	return 0, false
}

func (s *redisStore) zrem(key string, members []string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.touchUnlocked(key)
	if !ok || o.typ != typeZSet {
		return 0
	}
	mm := make(map[string]struct{}, len(members))
	for _, m := range members {
		mm[m] = struct{}{}
	}
	var n int64
	keep := o.zset[:0]
	for _, m := range o.zset {
		if _, hit := mm[m.member]; hit {
			n++
			continue
		}
		keep = append(keep, m)
	}
	o.zset = keep
	if len(o.zset) == 0 {
		delete(s.data, key)
	}
	return n
}

func (s *redisStore) zincrby(key string, delta float64, member string) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ensureUnlocked(key, typeZSet)
	if o == nil {
		return 0, false
	}
	for i := range o.zset {
		if o.zset[i].member == member {
			o.zset[i].score += delta
			return o.zset[i].score, true
		}
	}
	o.zset = append(o.zset, zmember{score: delta, member: member})
	return delta, true
}

// sortZSet 按 score 升序、score 相同按 member 字典序排序。
func sortZSet(ms []zmember) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].score != ms[j].score {
			return ms[i].score < ms[j].score
		}
		return ms[i].member < ms[j].member
	})
}

// normRange 把 redis 风格的 LRANGE/ZRANGE 起止索引（支持负数）归一化为切片闭区间 [lo,hi]。
// 无元素或越界时返回 lo>hi 表示空。
func normRange(start, stop, n int) (int, int) {
	if start < 0 {
		start = n + start
	}
	if start < 0 {
		start = 0
	}
	if stop < 0 {
		stop = n + stop
	}
	if stop >= n {
		stop = n - 1
	}
	if start > stop || start >= n {
		return 0, -1
	}
	return start, stop
}

// globToRegexp 把 redis KEYS 的 glob 模式（仅 * 与 ?）转成正则；其余按字面量转义。
func globToRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteString("\\")
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString("$")
	if re, err := regexp.Compile(b.String()); err == nil {
		return re
	}
	return regexp.MustCompile("^" + regexp.QuoteMeta(pattern) + "$")
}

func redisHandle(ctx context.Context, service *services.Service) {
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
	cfg := service.ServiceOptions.(redisConfig)
	store := cfg.store
	// INFO 伪信息：未配置或为空则回退到内置 fakeRedisInfo
	fakeInfo := resolveFakeInfo(cfg)

	srcAddr, err := common.GetConnSrcIPAndSrcPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "redis-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":         baseOptions.Protocol,
		"application":      baseOptions.Application,
		"redis.session-id": id.String(),
	}))

	pushClose := func() {
		event.EventPush(event.NewEvent(serviceName, "redis-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":         baseOptions.Protocol,
			"application":      baseOptions.Application,
			"redis.session-id": id.String(),
		}))
	}

	reader := bufio.NewReader(*conn)
	for {
		args, err := readCommand(reader)
		if err != nil {
			if err != io.EOF {
				logger.Log.Debug("redis read error:", err)
			}
			pushClose()
			return
		}
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		details := map[string]interface{}{
			"protocol":         baseOptions.Protocol,
			"application":      baseOptions.Application,
			"redis.session-id": id.String(),
			"redis.command":    cmd,
			"redis.args":       args,
		}

		// 高危操作把关键参数单独提取，便于还原攻击链
		switch cmd {
		case "AUTH":
			if len(args) >= 3 {
				details["redis.username"] = args[1]
				details["redis.password"] = args[2]
			} else if len(args) >= 2 {
				details["redis.password"] = args[1]
			}
		case "CONFIG":
			if len(args) >= 3 {
				details["redis.config_action"] = strings.ToUpper(args[1])
				details["redis.config_param"] = args[2]
				if len(args) >= 4 {
					details["redis.config_value"] = args[3]
				}
			}
		case "SLAVEOF", "REPLICAOF":
			if len(args) >= 3 {
				details["redis.replica_host"] = args[1]
				details["redis.replica_port"] = args[2]
			}
		case "MODULE":
			if len(args) >= 2 && strings.ToUpper(args[1]) == "LOAD" && len(args) >= 3 {
				details["redis.module_path"] = args[2]
			}
		}

		event.EventPush(event.NewEvent(serviceName, "redis-command", srcAddr, dstAddr, details))

		resp := processCommand(args, store, fakeInfo)
		if _, err := (*conn).Write(resp); err != nil {
			pushClose()
			return
		}

		// QUIT：回 +OK 后主动断开
		if cmd == "QUIT" {
			pushClose()
			return
		}
	}
}

// readCommand 读取一条 RESP 命令（支持多 bulk 数组与内联命令），返回参数字符串切片。
func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, nil
	}
	if line[0] == '*' {
		count, err := strconv.Atoi(line[1:])
		if err != nil || count < 0 {
			return nil, fmt.Errorf("bad multibulk header: %q", line)
		}
		args := make([]string, 0, count)
		for i := 0; i < count; i++ {
			h, err := readLine(r)
			if err != nil {
				return nil, err
			}
			if len(h) == 0 || h[0] != '$' {
				return nil, fmt.Errorf("bad bulk header: %q", h)
			}
			blen, err := strconv.Atoi(h[1:])
			if err != nil || blen < 0 {
				return nil, fmt.Errorf("bad bulk length: %q", h)
			}
			if blen > maxBulk {
				return nil, fmt.Errorf("bulk too large: %d", blen)
			}
			if blen == 0 {
				args = append(args, "")
				continue
			}
			buf := make([]byte, blen+2) // 数据 + \r\n
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
			args = append(args, string(buf[:blen]))
		}
		return args, nil
	}
	// 内联命令（如 redis-cli 直接键盘输入）
	return strings.Fields(line), nil
}

// readLine 读取到 \n 为止的一行，并去掉末尾的 \r\n。
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// processCommand 返回该命令对应的 RESP 响应字节；store 为该实例共享内存数据，
// fakeInfo 为 INFO 命令返回的伪信息（已由调用方完成空值回退）。
func processCommand(args []string, store *redisStore, fakeInfo string) []byte {
	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "PING":
		if len(args) >= 2 {
			return respSimple(args[1])
		}
		return respSimple("PONG")
	case "ECHO":
		if len(args) >= 2 {
			return respBulk(args[1])
		}
		return respNil()
	case "AUTH":
		// 蜜罐：永远成功，口令已在事件里捕获
		return respSimple("OK")
	case "HELLO":
		// redis 6+ 客户端首条握手；返回 RESP2 兼容的 map（扁平数组）
		return helloResponse()
	case "COMMAND":
		return respArrayHeader(0)
	case "INFO":
		return respBulk(fakeInfo)
	case "SELECT":
		return respSimple("OK")
	case "CONFIG":
		if len(args) >= 2 && strings.ToUpper(args[1]) == "GET" {
			param := ""
			if len(args) >= 3 {
				param = args[2]
			}
			return cat(respArrayHeader(2), respBulk(param), respBulk(configGet(param)))
		}
		return respSimple("OK")
	case "SLAVEOF", "REPLICAOF":
		return respSimple("OK")
	case "MODULE":
		return respSimple("OK")
	case "SET":
		return cmdSet(args, store)
	case "GET":
		if v, ok := store.getString(arg1(args)); ok {
			return respBulk(v)
		}
		return respNil()
	case "DEL":
		return respInt(store.del(args[1:]))
	case "EXISTS":
		return respInt(store.exists(args[1:]))
	case "KEYS":
		pattern := "*"
		if len(args) >= 2 {
			pattern = args[1]
		}
		return respBulkArray(store.keys(pattern))
	case "SCAN":
		cursor := "0"
		pattern := "*"
		count := 10
		if len(args) >= 2 {
			cursor = args[1]
		}
		for i := 2; i < len(args); i++ {
			switch strings.ToUpper(args[i]) {
			case "MATCH":
				if i+1 < len(args) {
					pattern = args[i+1]
					i++
				}
			case "COUNT":
				if i+1 < len(args) {
					if c, err := strconv.Atoi(args[i+1]); err == nil {
						count = c
					}
					i++
				}
			}
		}
		next, ks := store.scan(cursor, pattern, count)
		parts := [][]byte{respArrayHeader(2), respBulk(next), respArrayHeader(len(ks))}
		for _, k := range ks {
			parts = append(parts, respBulk(k))
		}
		return cat(parts...)
	case "TYPE":
		return respSimple(store.typeName(arg1(args)))
	case "TTL":
		return respInt(store.ttl(arg1(args)))
	case "PTTL":
		return respInt(store.pttl(arg1(args)))
	case "EXPIRE":
		if len(args) >= 3 {
			if secs, err := strconv.ParseInt(args[2], 10, 64); err == nil {
				if store.expire(arg1(args), secs*1000) {
					return respInt(1)
				}
			}
		}
		return respInt(0)
	case "PEXPIRE":
		if len(args) >= 3 {
			if ms, err := strconv.ParseInt(args[2], 10, 64); err == nil {
				if store.expire(arg1(args), ms) {
					return respInt(1)
				}
			}
		}
		return respInt(0)
	case "PERSIST":
		if store.persist(arg1(args)) {
			return respInt(1)
		}
		return respInt(0)
	case "APPEND":
		if len(args) >= 3 {
			return respInt(int64(store.appendStr(arg1(args), args[2])))
		}
		return respInt(0)
	case "STRLEN":
		return respInt(int64(store.strlen(arg1(args))))
	case "INCR":
		return respInt(store.incr(arg1(args), 1))
	case "DECR":
		return respInt(store.incr(arg1(args), -1))
	case "INCRBY":
		if len(args) >= 3 {
			if d, err := strconv.ParseInt(args[2], 10, 64); err == nil {
				return respInt(store.incr(arg1(args), d))
			}
		}
		return respError("ERR wrong number of arguments for 'incrby'")
	case "DECRBY":
		if len(args) >= 3 {
			if d, err := strconv.ParseInt(args[2], 10, 64); err == nil {
				return respInt(store.incr(arg1(args), -d))
			}
		}
		return respError("ERR wrong number of arguments for 'decrby'")
	case "GETSET":
		if len(args) >= 3 {
			old, ok := store.getset(arg1(args), args[2])
			if ok {
				return respBulk(old)
			}
			return respNil()
		}
		return respError("ERR wrong number of arguments for 'getset'")
	case "SETNX":
		if len(args) >= 3 && store.setnx(arg1(args), args[2]) {
			return respInt(1)
		}
		return respInt(0)
	case "MSET":
		if len(args) >= 3 {
			store.mset(args[1:])
		}
		return respSimple("OK")
	case "MGET":
		vs := store.mget(args[1:])
		parts := [][]byte{respArrayHeader(len(vs))}
		for _, v := range vs {
			if v == nil {
				parts = append(parts, respNil())
			} else {
				parts = append(parts, respBulk(*v))
			}
		}
		return cat(parts...)
	case "RENAME", "RENAMENX":
		if len(args) >= 3 {
			src, dst := args[1], args[2]
			if cmd == "RENAMENX" && store.exists([]string{dst}) > 0 {
				return respInt(0)
			}
			if store.rename(src, dst) {
				if cmd == "RENAMENX" {
					return respInt(1)
				}
				return respSimple("OK")
			}
			return respError("ERR no such key")
		}
		return respError("ERR wrong number of arguments")
	case "DBSIZE":
		return respInt(int64(store.size()))
	case "FLUSHALL", "FLUSHDB":
		store.flush()
		return respSimple("OK")

	// ---- 哈希 ----
	case "HSET", "HMSET":
		if len(args) >= 4 {
			added := store.hset(arg1(args), args[2:])
			if added < 0 {
				return respWrongType()
			}
			return respInt(added)
		}
		return respError("ERR wrong number of arguments for 'hset'")
	case "HGET":
		if len(args) >= 3 {
			if store.isWrongType(arg1(args), typeHash) {
				return respWrongType()
			}
			if v, ok := store.hget(arg1(args), args[2]); ok {
				return respBulk(v)
			}
			return respNil()
		}
		return respError("ERR wrong number of arguments for 'hget'")
	case "HMGET":
		if store.isWrongType(arg1(args), typeHash) {
			return respWrongType()
		}
		vs := store.hmget(arg1(args), args[2:])
		parts := [][]byte{respArrayHeader(len(vs))}
		for _, v := range vs {
			if v == nil {
				parts = append(parts, respNil())
			} else {
				parts = append(parts, respBulk(*v))
			}
		}
		return cat(parts...)
	case "HGETALL":
		if store.isWrongType(arg1(args), typeHash) {
			return respWrongType()
		}
		fields, values := store.hgetAll(arg1(args))
		if fields == nil {
			return respArrayHeader(0)
		}
		parts := [][]byte{respArrayHeader(len(fields) * 2)}
		for i, f := range fields {
			parts = append(parts, respBulk(f), respBulk(values[i]))
		}
		return cat(parts...)
	case "HDEL":
		if len(args) >= 3 {
			if store.isWrongType(arg1(args), typeHash) {
				return respWrongType()
			}
			return respInt(store.hdel(arg1(args), args[2:]))
		}
		return respInt(0)
	case "HLEN":
		if store.isWrongType(arg1(args), typeHash) {
			return respWrongType()
		}
		return respInt(store.hlen(arg1(args)))
	case "HKEYS":
		if store.isWrongType(arg1(args), typeHash) {
			return respWrongType()
		}
		return respBulkArray(store.hkeys(arg1(args)))
	case "HVALS":
		if store.isWrongType(arg1(args), typeHash) {
			return respWrongType()
		}
		return respBulkArray(store.hvals(arg1(args)))
	case "HINCRBY":
		if len(args) >= 4 {
			if d, err := strconv.ParseInt(args[3], 10, 64); err == nil {
				if store.isWrongType(arg1(args), typeHash) {
					return respWrongType()
				}
				if v, ok := store.hincrby(arg1(args), args[2], d); ok {
					return respInt(v)
				}
				return respWrongType()
			}
		}
		return respError("ERR wrong number of arguments for 'hincrby'")

	// ---- 列表 ----
	case "LPUSH":
		if len(args) >= 3 {
			if n := store.lpush(arg1(args), args[2:]); n >= 0 {
				return respInt(n)
			}
			return respWrongType()
		}
		return respError("ERR wrong number of arguments for 'lpush'")
	case "RPUSH":
		if len(args) >= 3 {
			if n := store.rpush(arg1(args), args[2:]); n >= 0 {
				return respInt(n)
			}
			return respWrongType()
		}
		return respError("ERR wrong number of arguments for 'rpush'")
	case "LRANGE":
		if len(args) >= 4 {
			if lo, e1 := strconv.Atoi(args[2]); e1 == nil {
				if hi, e2 := strconv.Atoi(args[3]); e2 == nil {
					return respBulkArray(store.lrange(arg1(args), lo, hi))
				}
			}
		}
		return respError("ERR wrong number of arguments for 'lrange'")
	case "LLEN":
		return respInt(store.llen(arg1(args)))
	case "LPOP":
		if v, ok := store.lpop(arg1(args)); ok {
			return respBulk(v)
		}
		return respNil()
	case "RPOP":
		if v, ok := store.rpop(arg1(args)); ok {
			return respBulk(v)
		}
		return respNil()

	// ---- 集合 ----
	case "SADD":
		if len(args) >= 3 {
			if n := store.sadd(arg1(args), args[2:]); n >= 0 {
				return respInt(n)
			}
			return respWrongType()
		}
		return respError("ERR wrong number of arguments for 'sadd'")
	case "SREM":
		if len(args) >= 3 {
			return respInt(store.srem(arg1(args), args[2:]))
		}
		return respInt(0)
	case "SMEMBERS":
		return respBulkArray(store.smembers(arg1(args)))
	case "SISMEMBER":
		if len(args) >= 3 {
			if store.sismember(arg1(args), args[2]) {
				return respInt(1)
			}
			return respInt(0)
		}
		return respInt(0)
	case "SCARD":
		return respInt(store.scard(arg1(args)))
	case "SINTER":
		if len(args) >= 2 {
			return respBulkArray(store.sinter(args[1:]))
		}
		return respError("ERR wrong number of arguments for 'sinter'")
	case "SUNION":
		if len(args) >= 2 {
			return respBulkArray(store.sunion(args[1:]))
		}
		return respError("ERR wrong number of arguments for 'sunion'")
	case "SDIFF":
		if len(args) >= 2 {
			return respBulkArray(store.sdiff(args[1:]))
		}
		return respError("ERR wrong number of arguments for 'sdiff'")

	// ---- 有序集合 ----
	case "ZADD":
		if len(args) >= 4 {
			elems, ok := parseZAdd(args[2:])
			if !ok {
				return respError("ERR syntax error")
			}
			if n, wt := store.zadd(arg1(args), elems); !wt {
				return respInt(n)
			}
			return respWrongType()
		}
		return respError("ERR wrong number of arguments for 'zadd'")
	case "ZRANGE":
		if len(args) >= 4 {
			if lo, e1 := strconv.Atoi(args[2]); e1 == nil {
				if hi, e2 := strconv.Atoi(args[3]); e2 == nil {
					withScores := false
					for _, a := range args[4:] {
						if strings.ToUpper(a) == "WITHSCORES" {
							withScores = true
						}
					}
					return respZRange(store.zrange(arg1(args), lo, hi), withScores)
				}
			}
		}
		return respError("ERR wrong number of arguments for 'zrange'")
	case "ZCARD":
		return respInt(store.zcard(arg1(args)))
	case "ZSCORE":
		if len(args) >= 3 {
			if sc, ok := store.zscore(arg1(args), args[2]); ok {
				return respBulk(formatScore(sc))
			}
			return respNil()
		}
		return respNil()
	case "ZRANK":
		if len(args) >= 3 {
			if r, ok := store.zrank(arg1(args), args[2]); ok {
				return respInt(r)
			}
			return respNil()
		}
		return respNil()
	case "ZREM":
		if len(args) >= 3 {
			return respInt(store.zrem(arg1(args), args[2:]))
		}
		return respInt(0)
	case "ZINCRBY":
		if len(args) >= 4 {
			if d, err := strconv.ParseFloat(args[2], 64); err == nil {
				if sc, ok := store.zincrby(arg1(args), d, args[3]); ok {
					return respBulk(formatScore(sc))
				}
				return respWrongType()
			}
		}
		return respError("ERR wrong number of arguments for 'zincrby'")

	// 其余（位图/GEO/HyperLogLog/发布订阅/脚本/事务/运维等）低交互：回 +OK，命令已落事件
	case "HSETNX", "HSTRLEN", "LPUSHX", "RPUSHX", "LSET", "LINSERT", "LREM",
		"LTRIM", "LINDEX", "BLPOP", "BRPOP", "BRPOPLPUSH", "LPOS", "LMOVE",
		"BLMOVE", "LMPOP", "SMOVE", "SSCAN", "ZSCAN", "HSCAN",
		"ZLEXCOUNT", "ZRANGEBYLEX", "ZREVRANGE", "ZREVRANK",
		"ZRANGEBYSCORE", "ZREVRANGEBYSCORE", "ZCOUNT", "ZPOPMIN", "ZPOPMAX",
		"ZRANDMEMBER", "ZINTERSTORE", "ZUNIONSTORE", "ZDIFF", "PFADD",
		"PFCOUNT", "PFMERGE", "GEOADD", "GEODIST", "GEOHASH", "GEOPOS",
		"GEORADIUS", "GEORADIUSBYMEMBER", "GEOSEARCH", "GEOSEARCHSTORE",
		"BITCOUNT", "BITOP", "BITFIELD", "BITPOS", "GETBIT", "SETBIT",
		"MOVE", "BGSAVE", "BGREWRITEAOF", "OBJECT", "DEBUG", "SLOWLOG",
		"CLIENT", "DISCARD", "MULTI", "EXEC", "SUBSCRIBE", "PUBLISH",
		"UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE", "WATCH", "UNWATCH",
		"SCRIPT", "EVAL", "EVALSHA", "FUNCTION", "RESTORE", "MIGRATE",
		"SWAPDB", "COPY", "SAVE", "LASTSAVE", "SHUTDOWN", "SLAVEEOF",
		"SYNC", "PSYNC", "MEMORY", "CLUSTER",
		"ACL", "ROLE", "RANDOMKEY", "UNLINK", "TOUCH", "EXPIREAT",
		"PEXPIREAT", "GETEX", "SETRANGE", "GETDEL", "LATENCY", "LOLWUT",
		"RESET", "FAILOVER":
		return respSimple("OK")
	case "TIME":
		now := time.Now()
		return cat(respArrayHeader(2),
			respBulk(strconv.FormatInt(now.Unix(), 10)),
			respBulk(strconv.FormatInt(int64(now.Nanosecond()/1000), 10)))
	case "QUIT":
		return respSimple("OK")
	default:
		// 宽容：未知命令也回 +OK，避免利用工具中断；命令本身已落事件
		return respSimple("OK")
	}
}

// arg1 取第一个参数（key），参数不足时返回空串。
func arg1(args []string) string {
	if len(args) >= 2 {
		return args[1]
	}
	return ""
}

// cmdSet 处理 SET 及其选项（EX/PX/NX/XX/KEEPTTL/GET 等），把值写入 store。
func cmdSet(args []string, store *redisStore) []byte {
	if len(args) < 3 {
		return respError("ERR wrong number of arguments for 'set'")
	}
	key := args[1]
	val := args[2]
	expireMs := int64(0)
	nx, xx := false, false
	for i := 3; i < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "EX":
			if i+1 < len(args) {
				if s, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					expireMs = s * 1000
				}
				i++
			}
		case "PX":
			if i+1 < len(args) {
				if s, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					expireMs = s
				}
				i++
			}
		case "NX":
			nx = true
		case "XX":
			xx = true
		case "EXAT", "PXAT", "KEEPTTL", "GET":
			// 低交互：绝对时间/保留 TTL/返回旧值均忽略
		}
	}
	if nx && store.exists([]string{key}) > 0 {
		return respNil()
	}
	if xx && store.exists([]string{key}) == 0 {
		return respNil()
	}
	store.setStr(key, val, expireMs)
	return respSimple("OK")
}

// ---- RESP 响应构造 ----

func respSimple(s string) []byte   { return []byte("+" + s + "\r\n") }
func respError(s string) []byte    { return []byte("-" + s + "\r\n") }
func respInt(n int64) []byte       { return []byte(":" + strconv.FormatInt(n, 10) + "\r\n") }
func respNil() []byte              { return []byte("$-1\r\n") }
func respBulk(s string) []byte     { return []byte("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n") }
func respArrayHeader(n int) []byte { return []byte("*" + strconv.Itoa(n) + "\r\n") }

func respWrongType() []byte {
	return respError("WRONGTYPE Operation against a key holding the wrong kind of value")
}

// respBulkArray 把字符串切片编码为 RESP 数组；nil/空切片均返回空数组。
func respBulkArray(keys []string) []byte {
	if keys == nil {
		keys = []string{}
	}
	parts := [][]byte{respArrayHeader(len(keys))}
	for _, k := range keys {
		parts = append(parts, respBulk(k))
	}
	return cat(parts...)
}

// respZRange 编码 ZRANGE 结果；withScores 时每个 member 后附带分数。
func respZRange(ms []zmember, withScores bool) []byte {
	if ms == nil {
		ms = []zmember{}
	}
	n := len(ms)
	if withScores {
		n *= 2
	}
	parts := [][]byte{respArrayHeader(n)}
	for _, m := range ms {
		parts = append(parts, respBulk(m.member))
		if withScores {
			parts = append(parts, respBulk(formatScore(m.score)))
		}
	}
	return cat(parts...)
}

// formatScore 按 redis 习惯输出 score：整数去尾零，否则用最短小数表示。
func formatScore(sc float64) string {
	if !math.IsInf(sc, 0) && sc == math.Trunc(sc) {
		return strconv.FormatInt(int64(sc), 10)
	}
	return strconv.FormatFloat(sc, 'g', -1, 64)
}

// parseZAdd 从 ZADD 的成员参数中过滤掉选项（NX/XX/CH/INCR/GT/LT），解析出 score/member 对。
func parseZAdd(args []string) ([]zmember, bool) {
	clean := make([]string, 0, len(args))
	for _, a := range args {
		switch strings.ToUpper(a) {
		case "NX", "XX", "CH", "INCR", "GT", "LT":
			// 选项忽略
		default:
			clean = append(clean, a)
		}
	}
	if len(clean)%2 != 0 {
		return nil, false
	}
	elems := make([]zmember, 0, len(clean)/2)
	for i := 0; i+1 < len(clean); i += 2 {
		sc, err := strconv.ParseFloat(clean[i], 64)
		if err != nil {
			return nil, false
		}
		elems = append(elems, zmember{score: sc, member: clean[i+1]})
	}
	return elems, true
}

// cat 拼接多个 RESP 片段（[]byte 不能用 + 直接相加）。
func cat(parts ...[]byte) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		b.Write(p)
	}
	return b.Bytes()
}

// helloResponse 返回 RESP2 兼容的 HELLO map（扁平 field/value 数组）。
func helloResponse() []byte {
	var b bytes.Buffer
	b.Write(respArrayHeader(14))
	b.Write(respBulk("server"))
	b.Write(respBulk("redis"))
	b.Write(respBulk("version"))
	b.Write(respBulk("7.0.11"))
	b.Write(respBulk("proto"))
	b.Write(respInt(2))
	b.Write(respBulk("id"))
	b.Write(respInt(1))
	b.Write(respBulk("mode"))
	b.Write(respBulk("standalone"))
	b.Write(respBulk("role"))
	b.Write(respBulk("master"))
	b.Write(respBulk("modules"))
	b.Write(respArrayHeader(0))
	return b.Bytes()
}

// configGet 对常见 CONFIG GET 参数返回伪值，未列出参数回空串。
func configGet(param string) string {
	switch strings.ToLower(param) {
	case "dir":
		return "/data"
	case "dbfilename":
		return "dump.rdb"
	case "requirepass":
		return ""
	case "bind":
		return "0.0.0.0"
	case "port":
		return "6379"
	case "maxmemory":
		return "0"
	case "appendonly":
		return "no"
	default:
		return ""
	}
}

const fakeRedisInfo = `# Server
redis_version:7.0.11
redis_mode:standalone
os:Linux 5.15.0 x86_64
arch_bits:64
multiplexing_api:epoll
# Clients
connected_clients:1
# Memory
used_memory:1024000
used_memory_human:1000.98K
maxmemory:0
# Persistence
loading:0
rdb_last_save_time:1700000000
# Replication
role:master
connected_slaves:0
# CPU
used_cpu_sys:0.10
used_cpu_user:0.08
`
