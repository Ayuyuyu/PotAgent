package mysql

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"potAgent/global"
	"potAgent/services"
)

// ---- 长度编码整数 ----

func TestLenEncInt(t *testing.T) {
	cases := []uint64{0, 1, 0xfa, 0xfb, 0xfc, 0xffff, 0x10000, 0xffffff, 0x1000000, 1 << 40}
	for _, v := range cases {
		b := appendLenEncInt(nil, v)
		got, n := readLenEncInt(b)
		if got != v || n != len(b) {
			t.Fatalf("lenenc roundtrip %d: got=%d n=%d len=%d", v, got, n, len(b))
		}
	}
	// 各区间编码长度：<0xfb 1 字节、<=0xffff 3、<=0xffffff 4、其余 9
	if n := len(appendLenEncInt(nil, 250)); n != 1 {
		t.Fatalf("small int should be 1 byte, got %d", n)
	}
	if n := len(appendLenEncInt(nil, 0x1000)); n != 3 {
		t.Fatalf("medium int should be 3 bytes, got %d", n)
	}
	if n := len(appendLenEncInt(nil, 0x100000)); n != 4 {
		t.Fatalf("large int should be 4 bytes, got %d", n)
	}
	if n := len(appendLenEncInt(nil, 1<<32)); n != 9 {
		t.Fatalf("huge int should be 9 bytes, got %d", n)
	}
	// 截断输入不应 panic
	if v, n := readLenEncInt([]byte{0xfc}); v != 0 || n != 0 {
		t.Fatalf("truncated should be zero: %d %d", v, n)
	}
}

// ---- 握手包 ----

func TestBuildGreeting(t *testing.T) {
	salt := []byte("0123456789abcdefghij")
	p := buildGreeting(mysqlConfig{Version: "5.7.42-log"}, 42, salt)

	if p[0] != 10 {
		t.Fatalf("protocol version = %d want 10", p[0])
	}
	if !strings.Contains(string(p), "5.7.42-log") {
		t.Fatalf("server version missing: %q", p)
	}
	if !strings.Contains(string(p), "mysql_native_password") {
		t.Fatalf("auth plugin missing: %q", p)
	}
	// thread id 42 位于 protocol(1) + version 串 + NUL 之后
	verEnd := 1 + len("5.7.42-log") + 1
	if p[verEnd] != 0x2a || p[verEnd+1] != 0 || p[verEnd+2] != 0 || p[verEnd+3] != 0 {
		t.Fatalf("thread id bytes = %x want 2a000000", p[verEnd:verEnd+4])
	}
	// salt 前 8 字节与后 12 字节都应出现
	if !strings.Contains(string(p), string(salt[:8])) {
		t.Fatalf("salt part1 missing")
	}
	if !strings.Contains(string(p), string(salt[8:20])) {
		t.Fatalf("salt part2 missing")
	}
	// auth_plugin_data_len = 21
	if !strings.Contains(string(p), "\x15") {
		t.Fatalf("auth_plugin_data_len(21) missing")
	}
}

// ---- 握手响应解析 ----

func appendTestHandshakeResponse(user, db, plugin string, authResp []byte, attrs [][2]string, useLenenc bool) []byte {
	flags := capProtocol41 | capSecureConnection | capPluginAuth | capConnectWithDB | capConnectAttrs
	if useLenenc {
		flags |= capPluginAuthLenenc
	}
	var p []byte
	p = append(p, byte(flags), byte(flags>>8), byte(flags>>16), byte(flags>>24))
	p = append(p, 0x00, 0x01, 0x00, 0x00) // max_packet
	p = append(p, 0x21)                   // charset
	p = append(p, make([]byte, 23)...)    // reserved
	p = appendNULString(p, user)
	if useLenenc {
		p = appendLenEncString(p, authResp)
	} else {
		p = append(p, byte(len(authResp)))
		p = append(p, authResp...)
	}
	p = appendNULString(p, db)
	p = appendNULString(p, plugin)
	var ab []byte
	for _, kv := range attrs {
		ab = appendLenEncString(ab, []byte(kv[0]))
		ab = appendLenEncString(ab, []byte(kv[1]))
	}
	p = appendLenEncInt(p, uint64(len(ab)))
	p = append(p, ab...)
	return p
}

func TestParseHandshakeResponse(t *testing.T) {
	attrs := [][2]string{{"_os", "Linux"}, {"_client_name", "mysql"}, {"_client_version", "8.0.36"}}
	b := appendTestHandshakeResponse("root", "webapp", "mysql_native_password",
		[]byte{0xde, 0xad, 0xbe, 0xef}, attrs, true)

	r, err := parseHandshakeResponse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.username != "root" {
		t.Fatalf("username=%q", r.username)
	}
	if r.database != "webapp" {
		t.Fatalf("database=%q", r.database)
	}
	if r.authPlugin != "mysql_native_password" {
		t.Fatalf("authPlugin=%q", r.authPlugin)
	}
	if string(r.authResponse) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("authResponse=%x", r.authResponse)
	}
	if r.attrs["_os"] != "Linux" || r.attrs["_client_name"] != "mysql" || r.attrs["_client_version"] != "8.0.36" {
		t.Fatalf("attrs=%v", r.attrs)
	}
	if r.charset != 0x21 {
		t.Fatalf("charset=%x", r.charset)
	}

	// 老式 1 字节长度编码也要能解析
	b2 := appendTestHandshakeResponse("bob", "", "", nil, nil, false)
	r2, err := parseHandshakeResponse(b2)
	if err != nil {
		t.Fatalf("parse legacy: %v", err)
	}
	if r2.username != "bob" || len(r2.authResponse) != 0 {
		t.Fatalf("legacy parse: %+v", r2)
	}

	// 空 auth_response（lenenc 0）
	b3 := appendTestHandshakeResponse("nopass", "db", "mysql_native_password", nil, nil, true)
	r3, err := parseHandshakeResponse(b3)
	if err != nil {
		t.Fatalf("parse empty auth: %v", err)
	}
	if r3.username != "nopass" || len(r3.authResponse) != 0 {
		t.Fatalf("empty auth: %+v", r3)
	}

	// 畸形输入应报错而不是 panic
	if _, err := parseHandshakeResponse([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("truncated should error")
	}
	if _, err := parseHandshakeResponse(nil); err == nil {
		t.Fatalf("nil should error")
	}
}

// ---- SQL 归一化与查询分发 ----

func TestNormalizeSQL(t *testing.T) {
	cases := map[string]string{
		"  SELECT   VERSION() ; ": "select version()",
		"select\t*\nfrom users":   "select * from users",
		"SHOW DATABASES":          "show databases",
	}
	for in, want := range cases {
		if got := normalizeSQL(in); got != want {
			t.Fatalf("normalizeSQL(%q)=%q want %q", in, got, want)
		}
	}
}

func testSession() *mysqlSession {
	return &mysqlSession{
		cfg:  mysqlConfig{Version: "5.7.42-log", Databases: []string{"information_schema", "test"}, Tables: []string{"users"}},
		db:   "test",
		user: "root",
		push: func(string, map[string]interface{}) {},
	}
}

func TestAnswerVersionAndUser(t *testing.T) {
	s := testSession()
	rs, ok := s.answer("SELECT VERSION()")
	if !ok || len(rs.columns) != 1 || rs.columns[0].name != "VERSION()" {
		t.Fatalf("version(): %+v ok=%v", rs, ok)
	}
	if len(rs.rows) != 1 || *rs.rows[0][0] != "5.7.42-log" {
		t.Fatalf("version value: %+v", rs.rows)
	}

	rs, ok = s.answer("select @@version")
	if !ok || *rs.rows[0][0] != "5.7.42-log" {
		t.Fatalf("@@version: %+v", rs.rows)
	}

	rs, _ = s.answer("select user()")
	if *rs.rows[0][0] != "root@localhost" {
		t.Fatalf("user(): %+v", rs.rows)
	}

	rs, _ = s.answer("select database()")
	if *rs.rows[0][0] != "test" {
		t.Fatalf("database(): %+v", rs.rows)
	}

	// 未选库时 database() 应为 NULL
	s.db = ""
	rs, _ = s.answer("select database()")
	if rs.rows[0][0] != nil {
		t.Fatalf("database() should be NULL, got %v", *rs.rows[0][0])
	}
}

func TestAnswerShowCommands(t *testing.T) {
	s := testSession()

	rs, ok := s.answer("show databases")
	if !ok || len(rs.columns) != 1 || rs.columns[0].name != "Database" {
		t.Fatalf("show databases columns: %+v", rs.columns)
	}
	if len(rs.rows) != 2 || *rs.rows[0][0] != "information_schema" {
		t.Fatalf("show databases rows: %+v", rs.rows)
	}

	rs, _ = s.answer("show tables")
	if rs.columns[0].name != "Tables_in_test" {
		t.Fatalf("show tables col: %q", rs.columns[0].name)
	}
	if len(rs.rows) != 1 || *rs.rows[0][0] != "users" {
		t.Fatalf("show tables rows: %+v", rs.rows)
	}

	rs, _ = s.answer("show variables like 'version'")
	if len(rs.columns) != 2 || rs.columns[0].name != "Variable_name" {
		t.Fatalf("show variables columns: %+v", rs.columns)
	}
	found := false
	for _, row := range rs.rows {
		if *row[0] == "version" && *row[1] == "5.7.42-log" {
			found = true
		}
	}
	if !found {
		t.Fatalf("version variable missing: %+v", rs.rows)
	}

	rs, _ = s.answer("show grants")
	if len(rs.rows) == 0 || !strings.Contains(*rs.rows[0][0], "GRANT ALL PRIVILEGES") {
		t.Fatalf("show grants: %+v", rs.rows)
	}
}

// TestFlavorDefaults 验证 MySQL / MariaDB / Percona 三者的默认指纹差异
// （同一 3306 端口，单看大版本号分不清，需要按风味判别）。
func TestFlavorDefaults(t *testing.T) {
	cases := []struct {
		version     string
		wantPlugin  string
		wantSQLMode string
		wantComment string
	}{
		{
			version:     "8.0.36",
			wantPlugin:  "caching_sha2_password",
			wantSQLMode: "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
			wantComment: "MySQL Community Server - GPL",
		},
		{
			version:     "5.7.42-log",
			wantPlugin:  "mysql_native_password",
			wantSQLMode: "NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES",
			wantComment: "MySQL Community Server - GPL",
		},
		{
			// MariaDB 大版本号 10 ≥ 8，但不能伪装成 MySQL 8：
			// 默认插件仍 native，sql_mode 是 MariaDB 风格（无 ONLY_FULL_GROUP_BY）。
			version:     "10.11.5-MariaDB",
			wantPlugin:  "mysql_native_password",
			wantSQLMode: "STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION",
			wantComment: "MariaDB",
		},
		{
			version:     "10.6.18-MariaDB-1:10.6.18+maria~ubu2204",
			wantPlugin:  "mysql_native_password",
			wantSQLMode: "STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION",
			wantComment: "MariaDB",
		},
		{
			version:     "8.0.36-28 Percona Server",
			wantPlugin:  "caching_sha2_password",
			wantSQLMode: "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
			wantComment: "Percona Server (GPL)",
		},
	}
	for _, tc := range cases {
		c := mysqlConfig{Version: tc.version}
		if got := c.authPlugin(); got != tc.wantPlugin {
			t.Fatalf("%s authPlugin=%q want %q", tc.version, got, tc.wantPlugin)
		}
		if got := c.sqlMode(); got != tc.wantSQLMode {
			t.Fatalf("%s sqlMode=%q want %q", tc.version, got, tc.wantSQLMode)
		}
		if got := c.versionComment(); got != tc.wantComment {
			t.Fatalf("%s versionComment=%q want %q", tc.version, got, tc.wantComment)
		}
	}
}

func TestAnswerInfoSchema(t *testing.T) {
	s := testSession()

	rs, _ := s.answer("select * from information_schema.schemata")
	if len(rs.rows) != 2 || *rs.rows[0][0] != "information_schema" {
		t.Fatalf("schemata rows=%d first=%q", len(rs.rows), *rs.rows[0][0])
	}

	rs, _ = s.answer("select table_schema, table_name from information_schema.tables")
	if len(rs.rows) != 2 {
		t.Fatalf("tables rows=%d", len(rs.rows))
	}

	rs, _ = s.answer("select * from information_schema.columns where table_name='users'")
	if len(rs.rows) != 3 {
		t.Fatalf("columns rows=%d", len(rs.rows))
	}
	// 应包含 password 列（诱使攻击者认为有戏）
	found := false
	for _, row := range rs.rows {
		if *row[2] == "password" {
			found = true
		}
	}
	if !found {
		t.Fatalf("password column missing: %+v", rs.rows)
	}
}

func TestAnswerWriteOps(t *testing.T) {
	s := testSession()
	for _, sql := range []string{
		"create table x (a int)",
		"insert into users values (1)",
		"update users set pwd='1'",
		"set @a=1",
		"grant all on *.* to 'x'@'%'",
	} {
		if _, ok := s.answer(sql); ok {
			t.Fatalf("%q should be answered with OK, not a result set", sql)
		}
	}

	// 未识别的读操作回单列空结果集
	rs, ok := s.answer("select 1 from dual where x")
	if !ok || len(rs.columns) != 1 || len(rs.rows) != 0 {
		t.Fatalf("generic select: %+v ok=%v", rs, ok)
	}

	// USE db 会切库
	if _, ok := s.answer("USE webapp"); ok {
		t.Fatalf("use should be OK")
	}
	if s.db != "webapp" {
		t.Fatalf("use should switch db, got %q", s.db)
	}
}

// ---- 响应包 ----

func TestResponsePackets(t *testing.T) {
	ok := buildOKPacket(0, 0, statusAutocommit)
	if ok[0] != 0x00 {
		t.Fatalf("OK header=%x", ok[0])
	}

	eof := buildEOFPacket(statusAutocommit)
	if eof[0] != 0xfe {
		t.Fatalf("EOF header=%x", eof[0])
	}
	if len(eof) != 5 {
		t.Fatalf("EOF len=%d want 5", len(eof))
	}

	err := buildErrPacket(1045, "28000", "Access denied")
	if err[0] != 0xff || err[3] != '#' {
		t.Fatalf("ERR header=%x marker=%q", err[0], err[3])
	}
	if !strings.Contains(string(err), "Access denied") {
		t.Fatalf("ERR msg missing: %q", err)
	}

	prep := buildStmtPrepareOK()
	if prep[0] != 0x00 {
		t.Fatalf("stmt prepare header=%x", prep[0])
	}
}

// ---- TCP 端到端 ----

type testClient struct {
	c *mysqlConn
	t *testing.T
}

func startTestServer(t *testing.T, cfg mysqlConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := &services.Service{
		BaseOptions:    global.ServiceBaseConfig{Protocol: "mysql", Application: "mysql"},
		ServiceOptions: cfg,
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(c, svc)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func (tc *testClient) read() []byte {
	p, err := tc.c.readPacket()
	if err != nil {
		tc.t.Fatalf("read packet: %v", err)
	}
	return p
}

func (tc *testClient) send(p []byte) {
	if err := tc.c.writePacket(p); err != nil {
		tc.t.Fatalf("write packet: %v", err)
	}
}

func (tc *testClient) query(sql string) []byte {
	tc.send(append([]byte{comQuery}, sql...))
	return tc.read()
}

// readResultSet 读一个完整结果集，返回列名与行（nil 元素 = NULL）。
func (tc *testClient) readResultSet() ([]string, [][]*string) {
	cnt := tc.read()
	n, _ := readLenEncInt(cnt)
	cols := make([]string, 0, n)
	for i := uint64(0); i < n; i++ {
		def := tc.read()
		pos := 0
		for j := 0; j < 5; j++ {
			l, adv := readLenEncInt(def[pos:])
			if j == 4 {
				cols = append(cols, string(def[pos+adv:pos+adv+int(l)]))
			}
			pos += adv + int(l)
		}
	}
	if n > 0 {
		if eof := tc.read(); eof[0] != 0xfe {
			tc.t.Fatalf("expected EOF after columns, got %x", eof[0])
		}
	}
	var rows [][]*string
	for {
		row := tc.read()
		if row[0] == 0xfe && len(row) < 9 {
			break // EOF
		}
		cells := make([]*string, 0)
		pos := 0
		for pos < len(row) {
			if row[pos] == 0xfb {
				cells = append(cells, nil)
				pos++
				continue
			}
			l, adv := readLenEncInt(row[pos:])
			pos += adv
			v := string(row[pos : pos+int(l)])
			cells = append(cells, &v)
			pos += int(l)
		}
		rows = append(rows, cells)
	}
	return cols, rows
}

func TestEndToEndHandshakeAndQuery(t *testing.T) {
	addr, stop := startTestServer(t, mysqlConfig{
		Version:   "5.7.42-log",
		Databases: []string{"information_schema", "test"},
		Tables:    []string{"users"},
	})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := &testClient{c: &mysqlConn{conn: conn, br: bufio.NewReader(conn)}, t: t}

	// 1) 服务端握手
	greeting := tc.read()
	if greeting[0] != 10 {
		t.Fatalf("greeting protocol=%d", greeting[0])
	}
	if !strings.Contains(string(greeting), "5.7.42-log") {
		t.Fatalf("greeting version missing: %q", greeting)
	}

	// 2) 客户端握手响应（带凭证与客户端属性）
	tc.send(appendTestHandshakeResponse("root", "test", "mysql_native_password",
		[]byte{1, 2, 3, 4, 5}, [][2]string{{"_os", "Linux"}, {"_client_name", "mysql"}}, true))

	// 3) 认证结果：不校验，一律 OK
	authResult := tc.read()
	if authResult[0] != 0x00 {
		t.Fatalf("auth result header=%x want OK(0x00)", authResult[0])
	}

	// 4) COM_QUERY：SELECT VERSION()
	cols, rows := tc.queryResultSet("SELECT VERSION()")
	if len(cols) != 1 || cols[0] != "VERSION()" {
		t.Fatalf("version columns=%v", cols)
	}
	if len(rows) != 1 || *rows[0][0] != "5.7.42-log" {
		t.Fatalf("version rows=%v", rows)
	}

	// 5) SHOW DATABASES
	cols, rows = tc.queryResultSet("SHOW DATABASES")
	if cols[0] != "Database" || len(rows) != 2 {
		t.Fatalf("show databases: cols=%v rows=%d", cols, len(rows))
	}

	// 6) information_schema.tables
	cols, rows = tc.queryResultSet("select table_name from information_schema.tables")
	if len(cols) != 1 || len(rows) != 2 {
		t.Fatalf("info schema: cols=%v rows=%d", cols, len(rows))
	}

	// 7) 写操作回 OK
	if p := tc.query("CREATE TABLE t (a int)"); p[0] != 0x00 {
		t.Fatalf("create table should be OK, got %x", p[0])
	}

	// 8) 未识别的读操作：回单列空结果集（合法，不挂服务）
	if cols, rows := tc.queryResultSet("select bogus from nowhere"); len(cols) != 1 || len(rows) != 0 {
		t.Fatalf("generic select should be 1 empty column, got cols=%v rows=%d", cols, len(rows))
	}
	tc.send([]byte{comPing})
	if p := tc.read(); p[0] != 0x00 {
		t.Fatalf("ping should be OK, got %x", p[0])
	}

	// 9) COM_QUIT
	tc.send([]byte{comQuit})
}

// queryResultSet 发一条查询并读回完整结果集。
func (tc *testClient) queryResultSet(sql string) ([]string, [][]*string) {
	tc.send(append([]byte{comQuery}, sql...))
	return tc.readResultSet()
}

// TestEndToEndGarbage 验证畸形/恶意输入不会打挂服务。
func TestEndToEndGarbage(t *testing.T) {
	addr, stop := startTestServer(t, mysqlConfig{})
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := &testClient{c: &mysqlConn{conn: conn, br: bufio.NewReader(conn)}, t: t}

	tc.read() // greeting
	// 空握手响应（只有命令字节 0x03，无协议字段）-> 服务端回 ERR 后断开
	tc.send([]byte{0x03})
	if p := tc.read(); p[0] != 0xff {
		t.Fatalf("bad handshake should get ERR, got %x", p[0])
	}

	// 新连接仍然正常
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	tc2 := &testClient{c: &mysqlConn{conn: conn2, br: bufio.NewReader(conn2)}, t: t}
	if g := tc2.read(); g[0] != 10 {
		t.Fatalf("server should still work, greeting=%x", g[0])
	}
}
