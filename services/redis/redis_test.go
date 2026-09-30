package redis

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"

	"potAgent/services"
)

// buildRESP 构造一条 RESP 多 bulk 命令字节（测试用）。
func buildRESP(args ...string) []byte {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, a := range args {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteString("\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// newTestStore 构造一个空内存 store（与真实实例共享结构一致）。
func newTestStore() *redisStore {
	return &redisStore{data: make(map[string]*redisObject)}
}

// TestReadCommand 校验 RESP 多 bulk 与内联命令解析。
func TestReadCommand(t *testing.T) {
	// 多 bulk：*2\r\n$4\r\nPING\r\n$3\r\nabc\r\n
	in := buildRESP("PING", "abc")
	r := bufio.NewReader(strings.NewReader(string(in) + "PING\r\n")) // 末尾追加一条内联
	args1, err := readCommand(r)
	if err != nil {
		t.Fatalf("readCommand multibulk: %v", err)
	}
	if len(args1) != 2 || args1[0] != "PING" || args1[1] != "abc" {
		t.Fatalf("multibulk parsed wrong: %#v", args1)
	}
	args2, err := readCommand(r)
	if err != nil {
		t.Fatalf("readCommand inline: %v", err)
	}
	if len(args2) != 1 || args2[0] != "PING" {
		t.Fatalf("inline parsed wrong: %#v", args2)
	}
}

// TestProcessCommand 校验关键命令的响应构造。
func TestProcessCommand(t *testing.T) {
	cases := []struct {
		args   []string
		expect string
	}{
		{[]string{"PING"}, "+PONG\r\n"},
		{[]string{"PING", "hi"}, "+hi\r\n"},
		{[]string{"ECHO", "x"}, "$1\r\nx\r\n"},
		{[]string{"AUTH", "secret"}, "+OK\r\n"},
		{[]string{"QUIT"}, "+OK\r\n"},
		{[]string{"GET", "k"}, "$-1\r\n"},
		{[]string{"KEYS", "*"}, "*0\r\n"},
		{[]string{"DBSIZE"}, ":0\r\n"},
		{[]string{"CONFIG", "GET", "dir"}, "*2\r\n$3\r\ndir\r\n$5\r\n/data\r\n"},
		{[]string{"CONFIG", "SET", "dir", "/tmp"}, "+OK\r\n"},
		{[]string{"SLAVEOF", "1.2.3.4", "6379"}, "+OK\r\n"},
		{[]string{"MODULE", "LOAD", "/tmp/exp.so"}, "+OK\r\n"},
		{[]string{"UNKNOWNCMD"}, "+OK\r\n"},
	}
	for _, c := range cases {
		got := string(processCommand(c.args, newTestStore(), fakeRedisInfo))
		if got != c.expect {
			t.Errorf("processCommand(%v) = %q, want %q", c.args, got, c.expect)
		}
	}
}

// TestStoreFunctional 校验 SET/GET 等字符串命令真正读写同一份内存数据。
func TestStoreFunctional(t *testing.T) {
	store := newTestStore()

	if got := string(processCommand([]string{"SET", "foo", "bar"}, store, fakeRedisInfo)); got != "+OK\r\n" {
		t.Fatalf("SET = %q", got)
	}
	if got := string(processCommand([]string{"GET", "foo"}, store, fakeRedisInfo)); got != "$3\r\nbar\r\n" {
		t.Fatalf("GET after SET = %q, want $3\\r\\nbar\\r\\n", got)
	}

	if got := string(processCommand([]string{"SET", "foo", "baz"}, store, fakeRedisInfo)); got != "+OK\r\n" {
		t.Fatalf("SET overwrite = %q", got)
	}
	if got := string(processCommand([]string{"GET", "foo"}, store, fakeRedisInfo)); got != "$3\r\nbaz\r\n" {
		t.Fatalf("GET overwritten = %q", got)
	}

	processCommand([]string{"MSET", "a", "1", "b", "2"}, store, fakeRedisInfo)
	if got := string(processCommand([]string{"MGET", "a", "b", "foo"}, store, fakeRedisInfo)); got != "*3\r\n$1\r\n1\r\n$1\r\n2\r\n$3\r\nbaz\r\n" {
		t.Fatalf("MGET = %q", got)
	}

	if got := string(processCommand([]string{"INCR", "a"}, store, fakeRedisInfo)); got != ":2\r\n" {
		t.Fatalf("INCR = %q, want :2", got)
	}
	if got := string(processCommand([]string{"GET", "a"}, store, fakeRedisInfo)); got != "$1\r\n2\r\n" {
		t.Fatalf("GET a = %q", got)
	}

	if got := string(processCommand([]string{"EXISTS", "a", "foo"}, store, fakeRedisInfo)); got != ":2\r\n" {
		t.Fatalf("EXISTS = %q", got)
	}
	if got := string(processCommand([]string{"DEL", "a"}, store, fakeRedisInfo)); got != ":1\r\n" {
		t.Fatalf("DEL = %q", got)
	}
	if got := string(processCommand([]string{"EXISTS", "a"}, store, fakeRedisInfo)); got != ":0\r\n" {
		t.Fatalf("EXISTS after DEL = %q", got)
	}

	if got := string(processCommand([]string{"KEYS", "*"}, store, fakeRedisInfo)); got != "*2\r\n$3\r\nfoo\r\n$1\r\nb\r\n" && got != "*2\r\n$1\r\nb\r\n$3\r\nfoo\r\n" {
		t.Fatalf("KEYS * = %q", got)
	}

	if got := string(processCommand([]string{"TTL", "foo"}, store, fakeRedisInfo)); got != ":-1\r\n" {
		t.Fatalf("TTL no-expire = %q, want -1", got)
	}
	processCommand([]string{"EXPIRE", "foo", "100"}, store, fakeRedisInfo)
	if got := string(processCommand([]string{"TTL", "foo"}, store, fakeRedisInfo)); got != ":100\r\n" {
		t.Fatalf("TTL after EXPIRE = %q, want :100", got)
	}

	processCommand([]string{"FLUSHALL"}, store, fakeRedisInfo)
	if got := string(processCommand([]string{"DBSIZE"}, store, fakeRedisInfo)); got != ":0\r\n" {
		t.Fatalf("DBSIZE after FLUSHALL = %q, want :0", got)
	}
	if got := string(processCommand([]string{"GET", "foo"}, store, fakeRedisInfo)); got != "$-1\r\n" {
		t.Fatalf("GET after FLUSHALL = %q, want nil", got)
	}
}

// TestStoreTypes 校验 hash/list/set/zset 真存真取，覆盖常见攻击/运维操作。
func TestStoreTypes(t *testing.T) {
	store := newTestStore()

	// ---- Hash ----
	if got := string(processCommand([]string{"HSET", "user:1", "name", "bob", "age", "20"}, store, fakeRedisInfo)); got != ":2\r\n" {
		t.Fatalf("HSET = %q, want :2 (added 2 fields)", got)
	}
	if got := string(processCommand([]string{"HGET", "user:1", "name"}, store, fakeRedisInfo)); got != "$3\r\nbob\r\n" {
		t.Fatalf("HGET name = %q, want $3\\r\\nbob\\r\\n", got)
	}
	if got := string(processCommand([]string{"HGET", "user:1", "age"}, store, fakeRedisInfo)); got != "$2\r\n20\r\n" {
		t.Fatalf("HGET age = %q, want $2\\r\\n20\\r\\n", got)
	}
	hga := string(processCommand([]string{"HGETALL", "user:1"}, store, fakeRedisInfo))
	if !strings.HasPrefix(hga, "*4\r\n") || !strings.Contains(hga, "name") || !strings.Contains(hga, "bob") || !strings.Contains(hga, "age") || !strings.Contains(hga, "20") {
		t.Fatalf("HGETALL = %q, want flat field/value array", hga)
	}
	if got := string(processCommand([]string{"HLEN", "user:1"}, store, fakeRedisInfo)); got != ":2\r\n" {
		t.Fatalf("HLEN = %q, want :2", got)
	}
	if got := string(processCommand([]string{"HDEL", "user:1", "age"}, store, fakeRedisInfo)); got != ":1\r\n" {
		t.Fatalf("HDEL = %q, want :1", got)
	}
	if got := string(processCommand([]string{"HLEN", "user:1"}, store, fakeRedisInfo)); got != ":1\r\n" {
		t.Fatalf("HLEN after HDEL = %q, want :1", got)
	}
	if got := string(processCommand([]string{"HINCRBY", "user:1", "age", "5"}, store, fakeRedisInfo)); got != ":5\r\n" {
		t.Fatalf("HINCRBY = %q, want :5", got)
	}

	// ---- List ----
	if got := string(processCommand([]string{"LPUSH", "list1", "a", "b", "c"}, store, fakeRedisInfo)); got != ":3\r\n" {
		t.Fatalf("LPUSH = %q, want :3", got)
	}
	// LPUSH a b c → 表头为 c,b,a
	if got := string(processCommand([]string{"LRANGE", "list1", "0", "-1"}, store, fakeRedisInfo)); got != "*3\r\n$1\r\nc\r\n$1\r\nb\r\n$1\r\na\r\n" {
		t.Fatalf("LRANGE 0 -1 = %q, want c,b,a", got)
	}
	if got := string(processCommand([]string{"LLEN", "list1"}, store, fakeRedisInfo)); got != ":3\r\n" {
		t.Fatalf("LLEN = %q, want :3", got)
	}
	if got := string(processCommand([]string{"RPUSH", "list1", "z"}, store, fakeRedisInfo)); got != ":4\r\n" {
		t.Fatalf("RPUSH = %q, want :4", got)
	}

	// ---- Set ----
	if got := string(processCommand([]string{"SADD", "s1", "1", "2", "3"}, store, fakeRedisInfo)); got != ":3\r\n" {
		t.Fatalf("SADD = %q, want :3", got)
	}
	sm := string(processCommand([]string{"SMEMBERS", "s1"}, store, fakeRedisInfo))
	if !strings.HasPrefix(sm, "*3\r\n") || !strings.Contains(sm, "1") || !strings.Contains(sm, "2") || !strings.Contains(sm, "3") {
		t.Fatalf("SMEMBERS = %q, want 3 members", sm)
	}
	if got := string(processCommand([]string{"SISMEMBER", "s1", "2"}, store, fakeRedisInfo)); got != ":1\r\n" {
		t.Fatalf("SISMEMBER hit = %q, want :1", got)
	}
	if got := string(processCommand([]string{"SISMEMBER", "s1", "9"}, store, fakeRedisInfo)); got != ":0\r\n" {
		t.Fatalf("SISMEMBER miss = %q, want :0", got)
	}
	processCommand([]string{"SADD", "s2", "2", "3", "4"}, store, fakeRedisInfo)
	si := string(processCommand([]string{"SINTER", "s1", "s2"}, store, fakeRedisInfo))
	if !strings.Contains(si, "$1\r\n2\r\n") || !strings.Contains(si, "$1\r\n3\r\n") ||
		strings.Contains(si, "$1\r\n4\r\n") || strings.Contains(si, "$1\r\n1\r\n") {
		t.Fatalf("SINTER = %q, want {2,3}", si)
	}

	// ---- ZSet ----
	if got := string(processCommand([]string{"ZADD", "z1", "90", "math", "80", "english"}, store, fakeRedisInfo)); got != ":2\r\n" {
		t.Fatalf("ZADD = %q, want :2", got)
	}
	// 升序：english(80) 在前，math(90) 在后
	if got := string(processCommand([]string{"ZRANGE", "z1", "0", "-1"}, store, fakeRedisInfo)); got != "*2\r\n$7\r\nenglish\r\n$4\r\nmath\r\n" {
		t.Fatalf("ZRANGE = %q, want english,math", got)
	}
	if got := string(processCommand([]string{"ZRANGE", "z1", "0", "-1", "WITHSCORES"}, store, fakeRedisInfo)); got != "*4\r\n$7\r\nenglish\r\n$2\r\n80\r\n$4\r\nmath\r\n$2\r\n90\r\n" {
		t.Fatalf("ZRANGE WITHSCORES = %q", got)
	}
	if got := string(processCommand([]string{"ZSCORE", "z1", "math"}, store, fakeRedisInfo)); got != "$2\r\n90\r\n" {
		t.Fatalf("ZSCORE = %q, want $2\\r\\n90\\r\\n", got)
	}
	if got := string(processCommand([]string{"ZCARD", "z1"}, store, fakeRedisInfo)); got != ":2\r\n" {
		t.Fatalf("ZCARD = %q, want :2", got)
	}
	if got := string(processCommand([]string{"ZINCRBY", "z1", "10", "english"}, store, fakeRedisInfo)); got != "$2\r\n90\r\n" {
		t.Fatalf("ZINCRBY = %q, want $3\\r\\n90\\r\\n", got)
	}

	// ---- TYPE / SCAN / DBSIZE ----
	if got := string(processCommand([]string{"TYPE", "user:1"}, store, fakeRedisInfo)); got != "+hash\r\n" {
		t.Fatalf("TYPE user:1 = %q, want +hash", got)
	}
	if got := string(processCommand([]string{"TYPE", "list1"}, store, fakeRedisInfo)); got != "+list\r\n" {
		t.Fatalf("TYPE list1 = %q, want +list", got)
	}
	if got := string(processCommand([]string{"TYPE", "s1"}, store, fakeRedisInfo)); got != "+set\r\n" {
		t.Fatalf("TYPE s1 = %q, want +set", got)
	}
	if got := string(processCommand([]string{"TYPE", "z1"}, store, fakeRedisInfo)); got != "+zset\r\n" {
		t.Fatalf("TYPE z1 = %q, want +zset", got)
	}
	if got := string(processCommand([]string{"TYPE", "nope"}, store, fakeRedisInfo)); got != "+none\r\n" {
		t.Fatalf("TYPE missing = %q, want +none", got)
	}
	// 现有 5 个 key：user:1, list1, s1, s2, z1
	if got := string(processCommand([]string{"DBSIZE"}, store, fakeRedisInfo)); got != ":5\r\n" {
		t.Fatalf("DBSIZE = %q, want :5", got)
	}
	scan := string(processCommand([]string{"SCAN", "0", "MATCH", "*", "COUNT", "100"}, store, fakeRedisInfo))
	if !strings.HasPrefix(scan, "*2\r\n$1\r\n0\r\n") {
		t.Fatalf("SCAN = %q, want cursor 0 + array", scan)
	}
	if !strings.Contains(scan, "user:1") {
		t.Fatalf("SCAN missing user:1: %q", scan)
	}

	// ---- WRONGTYPE 防护 ----
	if got := string(processCommand([]string{"HGET", "list1", "x"}, store, fakeRedisInfo)); !strings.HasPrefix(got, "-WRONGTYPE") {
		t.Fatalf("HGET on list = %q, want WRONGTYPE error", got)
	}
}

// TestInfoResponse 校验 INFO 返回伪信息含版本行；并验证可配置 fake_info 与空值回退。
func TestInfoResponse(t *testing.T) {
	// 默认（内置 fakeRedisInfo）：含版本行
	got := string(processCommand([]string{"INFO"}, newTestStore(), fakeRedisInfo))
	if !strings.HasPrefix(got, "$") || !strings.Contains(got, "redis_version:7.0.11") {
		t.Fatalf("INFO default response unexpected: %q", got)
	}

	// 自定义 fake_info：原样返回配置内容
	custom := "# Server\r\nredis_version:6.2.7\r\n"
	gotCustom := string(processCommand([]string{"INFO"}, newTestStore(), custom))
	if !strings.Contains(gotCustom, "redis_version:6.2.7") {
		t.Fatalf("INFO custom response missing configured version: %q", gotCustom)
	}

	// 空值回退：resolveFakeInfo 在 FakeInfo 为空时返回内置内容
	gotEmpty := string(processCommand([]string{"INFO"}, newTestStore(), resolveFakeInfo(redisConfig{})))
	if !strings.Contains(gotEmpty, "redis_version:7.0.11") {
		t.Fatalf("INFO empty fallback unexpected: %q", gotEmpty)
	}
}

// TestRedisServiceRoundTrip 起真实 TCP 监听，验证 RESP 往返。
func TestRedisServiceRoundTrip(t *testing.T) {
	var svc services.Service = RedisServiceInit()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleServiceConn(&c, &svc)
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(buildRESP("PING")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readLineStr(t, conn); resp != "+PONG\r\n" {
		t.Fatalf("PING resp = %q, want +PONG", resp)
	}

	if _, err := conn.Write(buildRESP("AUTH", "admin123")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readLineStr(t, conn); resp != "+OK\r\n" {
		t.Fatalf("AUTH resp = %q, want +OK", resp)
	}

	if _, err := conn.Write(buildRESP("CONFIG", "SET", "dir", "/var/spool/cron")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readLineStr(t, conn); resp != "+OK\r\n" {
		t.Fatalf("CONFIG SET resp = %q, want +OK", resp)
	}

	if _, err := conn.Write(buildRESP("SET", "session", "admin-token")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readLineStr(t, conn); resp != "+OK\r\n" {
		t.Fatalf("SET resp = %q, want +OK", resp)
	}
	if _, err := conn.Write(buildRESP("GET", "session")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readResp(t, conn); resp != "$11\r\nadmin-token\r\n" {
		t.Fatalf("GET resp = %q, want $11\\r\\nadmin-token\\r\\n", resp)
	}

	// 真存真取往返：HSET 后 HGET 取回
	if _, err := conn.Write(buildRESP("HSET", "u", "name", "bob")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readLineStr(t, conn); resp != ":1\r\n" {
		t.Fatalf("HSET resp = %q, want :1", resp)
	}
	if _, err := conn.Write(buildRESP("HGET", "u", "name")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp := readResp(t, conn); resp != "$3\r\nbob\r\n" {
		t.Fatalf("HGET resp = %q, want $3\\r\\nbob\\r\\n", resp)
	}
}

func readLineStr(t *testing.T, conn net.Conn) string {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	return line
}

// readResp 读取完整 RESP 响应：bulk 类型（$ 开头）会连同值行一起读出。
func readResp(t *testing.T, conn net.Conn) string {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "$") {
		v, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read bulk: %v", err)
		}
		return line + "\r\n" + v
	}
	return line + "\r\n"
}
