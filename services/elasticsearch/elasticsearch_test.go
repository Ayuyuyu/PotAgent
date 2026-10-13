package elasticsearch

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"potAgent/global"
	"potAgent/services"
)

func TestSplitPath(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"/", 0},
		{"", 0},
		{"/_cluster/health", 2},
		{"/customer/_doc/1", 3},
		{"/customer", 1},
	}
	for _, c := range cases {
		got := splitPath(c.in)
		if len(got) != c.want {
			t.Fatalf("splitPath(%q) len=%d want %d (%q)", c.in, len(got), c.want, got)
		}
	}
	if splitPath("/a/b/c")[2] != "c" {
		t.Fatalf("splitPath last segment: %q", splitPath("/a/b/c")[2])
	}
}

func TestClassifyTarget(t *testing.T) {
	cases := []struct {
		method string
		path   string
		index  string
		docID  string
		action string
	}{
		{"GET", "/", "", "", "cluster_info"},
		{"GET", "/_cluster/health", "", "", "cluster_health"},
		{"GET", "/_cat/indices", "", "", "cat_indices"},
		{"GET", "/customer/_search", "customer", "", "search"},
		{"PUT", "/customer", "customer", "", "create_index"},
		{"DELETE", "/customer", "customer", "", "delete_index"},
		{"PUT", "/customer/_doc/1", "customer", "1", "index_doc"},
		{"GET", "/customer/_doc/1", "customer", "1", "get_doc"},
		{"POST", "/customer/_create", "customer", "", "create_doc"},
		{"POST", "/customer/_update/1", "customer", "1", "update_doc"},
		{"POST", "/_bulk", "", "", "bulk"},
		{"GET", "/customer/_count", "customer", "", "count"},
	}
	for _, c := range cases {
		idx, docID, action := classifyTarget(c.method, splitPath(c.path))
		if idx != c.index || docID != c.docID || action != c.action {
			t.Fatalf("classifyTarget(%s %s)=(%q,%q,%q) want (%q,%q,%q)",
				c.method, c.path, idx, docID, action, c.index, c.docID, c.action)
		}
	}
}

func TestParseBasicAuth(t *testing.T) {
	// "elastic:changeme" 的 base64
	user, pass, ok := parseBasicAuth("Basic ZWxhc3RpYzpjaGFuZ2VtZQ==")
	if !ok || user != "elastic" || pass != "changeme" {
		t.Fatalf("parseBasicAuth=(%q,%q,%v)", user, pass, ok)
	}
	// 非 Basic / 空值
	if _, _, ok := parseBasicAuth("Bearer abc"); ok {
		t.Fatalf("Bearer should not parse")
	}
	if _, _, ok := parseBasicAuth(""); ok {
		t.Fatalf("empty should not parse")
	}
}

// TestExtractScripts 覆盖 CVE-2015-1427 一类的 script_fields RCE 载荷提取。
func TestExtractScripts(t *testing.T) {
	body := `{"size":1,"script_fields":{"exploit":{"script":{"lang":"groovy","inline":"java.lang.Math.max(1,2)"}}}}`
	got := extractScripts([]byte(body))
	if len(got) == 0 {
		t.Fatalf("no script extracted from %s", body)
	}
	found := false
	for _, v := range got {
		if strings.Contains(v, "java.lang.Math.max") {
			found = true
		}
	}
	if !found {
		t.Fatalf("script payload missing: %v", got)
	}
	// 无 script 的普通 DSL 不应产生结果
	plain := `{"query":{"match_all":{}}}`
	if n := len(extractScripts([]byte(plain))); n != 0 {
		t.Fatalf("unexpected scripts: %v", extractScripts([]byte(plain)))
	}
	// 非法 JSON 不应 panic
	if n := len(extractScripts([]byte(`{not json`))); n != 0 {
		t.Fatalf("invalid json should yield nothing, got %v", n)
	}
}

func TestStoreCRUD(t *testing.T) {
	s := newESStore()
	s.ensureSeeded([]string{"customer", "orders"})

	if !s.hasIndex("customer") {
		t.Fatalf("seeded index missing")
	}
	if got := s.docCount("customer"); got != seedDocsPerIndex {
		t.Fatalf("seed docs=%d want %d", got, seedDocsPerIndex)
	}

	// 写入文档（自动 id）后可读回
	id, created, ver, seq := s.putDoc("customer", "", map[string]interface{}{"name": "alice"})
	if !created || id == "" || ver != 1 || seq == 0 {
		t.Fatalf("putDoc=(%q,%v,%d,%d)", id, created, ver, seq)
	}
	src, _, _, found := s.getDoc("customer", id)
	if !found || src["name"] != "alice" {
		t.Fatalf("getDoc=%v found=%v", src, found)
	}
	// 同 id 再写是 update，version 递增
	_, created2, ver2, _ := s.putDoc("customer", id, map[string]interface{}{"name": "bob"})
	if created2 || ver2 != 2 {
		t.Fatalf("update should not be created and version should bump: created=%v ver=%d", created2, ver2)
	}
	if s.docCount("customer") != seedDocsPerIndex+1 {
		t.Fatalf("doc count after insert=%d", s.docCount("customer"))
	}

	// 未配置的索引也能隐式创建（PUT _doc 到新索引）
	s.putDoc("attacker", "1", map[string]interface{}{"x": 1})
	if !s.hasIndex("attacker") {
		t.Fatalf("implicit index creation failed")
	}

	// 删除文档与索引
	if _, _, ok := s.deleteDoc("customer", id); !ok {
		t.Fatalf("deleteDoc failed")
	}
	if _, _, ok := s.deleteDoc("customer", "no-such-id"); ok {
		t.Fatalf("deleteDoc of missing id should fail")
	}
	if !s.deleteIndex("orders") {
		t.Fatalf("deleteIndex failed")
	}
	if s.deleteIndex("orders") {
		t.Fatalf("deleteIndex twice should fail")
	}
	if s.hasIndex("orders") {
		t.Fatalf("index still present after delete")
	}

	// searchHits：指定索引只回该索引
	if n := len(s.searchHits("customer")); n != seedDocsPerIndex {
		t.Fatalf("searchHits(customer)=%d want %d", n, seedDocsPerIndex)
	}
	if n := len(s.searchHits("")); n < seedDocsPerIndex {
		t.Fatalf("searchHits(all)=%d too few", n)
	}
	// _cat/indices 文本表格应含表头与索引名
	cat := s.catIndices()
	if !strings.Contains(cat, "docs.count") || !strings.Contains(cat, "customer") {
		t.Fatalf("catIndices output:\n%s", cat)
	}
}

func TestUpdateDocMerge(t *testing.T) {
	s := newESStore()
	s.putDoc("idx", "1", map[string]interface{}{"a": 1, "b": 2})
	created, ver, _ := s.updateDoc("idx", "1", map[string]interface{}{"b": 99})
	if created || ver != 2 {
		t.Fatalf("updateDoc=(%v,%d)", created, ver)
	}
	src, _, _, found := s.getDoc("idx", "1")
	if !found || src["a"] != 1 || src["b"] != 99 {
		t.Fatalf("merged doc=%v", src)
	}
}

// ---- HTTP 级集成测试 ----

// startTestServer 起一个 127.0.0.1 上的蜜罐实例，返回地址与停止函数。
func startTestServer(t *testing.T, cfg elasticsearchConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := &services.Service{
		BaseOptions:    global.ServiceBaseConfig{Protocol: "elasticsearch", Application: "elasticsearch"},
		ServiceOptions: cfg,
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(c, svc, cfg)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func testConfig() elasticsearchConfig {
	return elasticsearchConfig{
		store:       newESStore(),
		ClusterName: "elasticsearch",
		NodeName:    "node-1",
		Version:     "8.11.1",
		Tagline:     "You Know, for Search",
		Indices:     []string{"customer"},
	}
}

func do(t *testing.T, method, url string, body string, hdr map[string]string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func TestHTTPEndpoints(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 集群信息
	if code, body := do(t, "GET", base+"/", "", nil); code != 200 {
		t.Fatalf("GET / code=%d", code)
	} else if !strings.Contains(body, `"tagline":"You Know, for Search"`) ||
		!strings.Contains(body, `"cluster_name":"elasticsearch"`) ||
		!strings.Contains(body, `"number":"8.11.1"`) ||
		!strings.Contains(body, `"lucene_version":"9.8.0"`) ||
		!strings.Contains(body, `"minimum_wire_compatibility_version":"7.17.0"`) {
		t.Fatalf("GET / body: %s", body)
	}

	// 集群健康
	if code, body := do(t, "GET", base+"/_cluster/health", "", nil); code != 200 {
		t.Fatalf("health code=%d", code)
	} else if !strings.Contains(body, `"status":"green"`) {
		t.Fatalf("health body: %s", body)
	}

	// _cat/indices 文本表格
	if code, body := do(t, "GET", base+"/_cat/indices", "", nil); code != 200 {
		t.Fatalf("cat code=%d", code)
	} else if !strings.Contains(body, "customer") || !strings.Contains(body, "docs.count") {
		t.Fatalf("cat body: %s", body)
	}

	// 未知索引的 search 回 404 + index_not_found_exception
	if code, body := do(t, "GET", base+"/nosuch/_search", "", nil); code != 404 {
		t.Fatalf("search unknown index code=%d", code)
	} else if !strings.Contains(body, "index_not_found_exception") || !strings.Contains(body, "no such index [nosuch]") {
		t.Fatalf("404 body: %s", body)
	}

	// 未知端点回 ES 风格 404
	if code, _ := do(t, "GET", base+"/_nosuchapi", "", nil); code != 404 {
		t.Fatalf("unknown api code=%d", code)
	}
}

func TestHTTPDocLifecycle(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 写入文档
	if code, body := do(t, "PUT", base+"/customer/_doc/100", `{"name":"alice","role":"admin"}`, nil); code != 200 {
		t.Fatalf("PUT code=%d", code)
	} else if !strings.Contains(body, `"result":"created"`) || !strings.Contains(body, `"_id":"100"`) {
		t.Fatalf("PUT body: %s", body)
	}

	// 读回（真存真取）
	if code, body := do(t, "GET", base+"/customer/_doc/100", "", nil); code != 200 {
		t.Fatalf("GET code=%d", code)
	} else if !strings.Contains(body, `"found":true`) || !strings.Contains(body, `"role":"admin"`) {
		t.Fatalf("GET body: %s", body)
	}

	// _search 能命中
	if code, body := do(t, "POST", base+"/customer/_search", `{"query":{"match_all":{}}}`, nil); code != 200 {
		t.Fatalf("search code=%d", code)
	} else if !strings.Contains(body, `"hits"`) || !strings.Contains(body, `"alice"`) {
		t.Fatalf("search body: %s", body)
	}

	// _count
	if code, body := do(t, "GET", base+"/customer/_count", "", nil); code != 200 {
		t.Fatalf("count code=%d", code)
	} else if !strings.Contains(body, `"count":`) {
		t.Fatalf("count body: %s", body)
	}

	// 读不存在的文档回 404 且 found=false
	if code, body := do(t, "GET", base+"/customer/_doc/999", "", nil); code != 404 {
		t.Fatalf("get missing code=%d", code)
	} else if !strings.Contains(body, `"found":false`) {
		t.Fatalf("get missing body: %s", body)
	}

	// 删除文档
	if code, body := do(t, "DELETE", base+"/customer/_doc/100", "", nil); code != 200 {
		t.Fatalf("delete code=%d", code)
	} else if !strings.Contains(body, `"result":"deleted"`) {
		t.Fatalf("delete body: %s", body)
	}
	// 删除后读不到
	if code, _ := do(t, "GET", base+"/customer/_doc/100", "", nil); code != 404 {
		t.Fatalf("get after delete code=%d", code)
	}
}

func TestHTTPIndexAndBulk(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 建索引
	if code, body := do(t, "PUT", base+"/logs-2026", "", nil); code != 200 {
		t.Fatalf("create index code=%d", code)
	} else if !strings.Contains(body, `"acknowledged":true`) {
		t.Fatalf("create index body: %s", body)
	}
	// HEAD 存在性
	if code, _ := do(t, "HEAD", base+"/logs-2026", "", nil); code != 200 {
		t.Fatalf("HEAD existing index code=%d", code)
	}
	if code, _ := do(t, "HEAD", base+"/nope", "", nil); code != 404 {
		t.Fatalf("HEAD missing index code=%d", code)
	}

	// _bulk：index + create + delete 混合，且真实生效
	bulk := `{"index":{"_index":"logs-2026","_id":"b1"}}
{"msg":"first"}
{"create":{"_index":"logs-2026","_id":"b2"}}
{"msg":"second"}
{"delete":{"_index":"logs-2026","_id":"b1"}}
`
	if code, body := do(t, "POST", base+"/_bulk", bulk, map[string]string{"Content-Type": "application/x-ndjson"}); code != 200 {
		t.Fatalf("bulk code=%d", code)
	} else if !strings.Contains(body, `"result":"created"`) || !strings.Contains(body, `"result":"deleted"`) {
		t.Fatalf("bulk body: %s", body)
	}
	// b1 已删、b2 在
	if code, _ := do(t, "GET", base+"/logs-2026/_doc/b1", "", nil); code != 404 {
		t.Fatalf("bulk-deleted doc should be gone, code=%d", code)
	}
	if code, body := do(t, "GET", base+"/logs-2026/_doc/b2", "", nil); code != 200 {
		t.Fatalf("bulk-created doc code=%d", code)
	} else if !strings.Contains(body, `"msg":"second"`) {
		t.Fatalf("bulk-created doc body: %s", body)
	}

	// 删索引
	if code, body := do(t, "DELETE", base+"/logs-2026", "", nil); code != 200 {
		t.Fatalf("delete index code=%d", code)
	} else if !strings.Contains(body, `"acknowledged":true`) {
		t.Fatalf("delete index body: %s", body)
	}
	if code, _ := do(t, "GET", base+"/logs-2026/_search", "", nil); code != 404 {
		t.Fatalf("search after delete index code=%d", code)
	}
}

// TestHTTPKeepAlive 验证同一连接上可连续处理多个请求。
func TestHTTPKeepAlive(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		if _, err := fmt.Fprintf(conn, "GET /_cluster/health HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", addr); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("GET", "http://"+addr+"/_cluster/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(data), `"status":"green"`) {
			t.Fatalf("request %d response: %s", i, data)
		}
	}
}

// TestHTTPBadRequests 验证畸形 body / 非法 JSON 不会打挂服务。
func TestHTTPBadRequests(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 非 JSON body 写文档 -> 400 parse_exception
	if code, body := do(t, "PUT", base+"/customer/_doc/1", `not-json`, nil); code != 400 {
		t.Fatalf("bad json code=%d", code)
	} else if !strings.Contains(body, "parse_exception") {
		t.Fatalf("bad json body: %s", body)
	}

	// GET /<index>_doc 不带 id -> 400
	if code, _ := do(t, "GET", base+"/customer/_doc", "", nil); code != 400 {
		t.Fatalf("missing id code=%d", code)
	}

	// 服务仍然活着：后续请求正常
	if code, _ := do(t, "GET", base+"/_cluster/health", "", nil); code != 200 {
		t.Fatalf("service should still work, code=%d", code)
	}
}

func TestVersionProfile(t *testing.T) {
	cases := []struct{ in, lucene, wire, index string }{
		{"6.8.23", "7.7.3", "5.6.0", "5.0.0"},
		{"7.17.0", "8.11.1", "6.8.0", "6.0.0-beta1"},
		{"8.11.1", "9.8.0", "7.17.0", "7.0.0"},
		{"9.0.0", "10.1.0", "8.18.0", "8.0.0"},
	}
	for _, c := range cases {
		p := versionProfile(c.in)
		if p.lucene != c.lucene || p.minWireCompat != c.wire || p.minIndexCompat != c.index {
			t.Fatalf("versionProfile(%s)=%+v want lucene=%s wire=%s index=%s",
				c.in, p, c.lucene, c.wire, c.index)
		}
	}
	// 非法版本号应回落到默认版本的档案，而不是露馅的空值
	for _, in := range []string{"", "abc", "0.1.0", "x.y.z"} {
		if p := versionProfile(in); p.lucene != "9.8.0" {
			t.Fatalf("versionProfile(%q) should fall back to default profile, got %+v", in, p)
		}
	}
}

// TestVersionProfileDerivation 覆盖档案表里没有的新大版本（10/11/12…）。
func TestVersionProfileDerivation(t *testing.T) {
	for _, ver := range []string{"10.0.0", "11.3.2", "12.7.0"} {
		p := versionProfile(ver)
		major, minor, _ := parseVersion(ver)
		// Lucene 大版本 = ES 大版本 + 1
		if want := fmt.Sprintf("%d.%d.1", major+1, minor); p.lucene != want {
			t.Fatalf("versionProfile(%s).lucene=%q want %q", ver, p.lucene, want)
		}
		// 索引兼容下限 = 上一个 ES 大版本的 .0.0
		if want := fmt.Sprintf("%d.0.0", major-1); p.minIndexCompat != want {
			t.Fatalf("versionProfile(%s).minIndexCompat=%q want %q", ver, p.minIndexCompat, want)
		}
		if want := fmt.Sprintf("%d.17.0", major-1); p.minWireCompat != want {
			t.Fatalf("versionProfile(%s).minWireCompat=%q want %q", ver, p.minWireCompat, want)
		}
		if p.buildDate == "" {
			t.Fatalf("versionProfile(%s).buildDate empty", ver)
		}
	}
}

// TestVersionProfileOverride 覆盖 yaml 显式覆盖层（优先级最高）。
func TestVersionProfileOverride(t *testing.T) {
	cfg := testConfig()
	cfg.LuceneVersion = "10.9.9"
	cfg.BuildDate = "2025-01-01T00:00:00Z"
	cfg.MinWireCompatVersion = "8.19.0"
	cfg.MinIndexCompatVersion = "8.0.0"
	p := cfg.versionProfileOf()
	if p.lucene != "10.9.9" || p.buildDate != "2025-01-01T00:00:00Z" ||
		p.minWireCompat != "8.19.0" || p.minIndexCompat != "8.0.0" {
		t.Fatalf("override not applied: %+v", p)
	}
	// 不配覆盖时走档案表
	if p := testConfig().versionProfileOf(); p.lucene != "9.8.0" {
		t.Fatalf("no override should use table, got %+v", p)
	}
}

func TestParseVersionAndIndexCreated(t *testing.T) {
	if m, n, p := parseVersion("8.11.1"); m != 8 || n != 11 || p != 1 {
		t.Fatalf("parseVersion=(%d,%d,%d)", m, n, p)
	}
	if m, n, p := parseVersion("8.11"); m != 8 || n != 11 || p != 0 {
		t.Fatalf("parseVersion(short)=(%d,%d,%d)", m, n, p)
	}
	if m, _, _ := parseVersion("abc"); m != 0 {
		t.Fatalf("parseVersion(garbage) major=%d", m)
	}
	if got := indexCreated("7.17.0"); got != "7170099" {
		t.Fatalf("indexCreated(7.17.0)=%q want 7170099", got)
	}
	if got := indexCreated("8.11.1"); got != "8110199" {
		t.Fatalf("indexCreated(8.11.1)=%q want 8110199", got)
	}
}

func TestBuildHashStable(t *testing.T) {
	a, b := buildHash("8.11.1"), buildHash("8.11.1")
	if a != b || len(a) != 40 {
		t.Fatalf("buildHash not stable or wrong length: %q %q", a, b)
	}
	if buildHash("8.11.1") == buildHash("8.11.2") {
		t.Fatalf("different versions should have different build_hash")
	}
}

// TestHTTPPretty 验证 ?pretty / ?pretty=true / ?pretty=false 三种形态。
func TestHTTPPretty(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// ?pretty 与 ?pretty=true 都应返回缩进 JSON
	for _, q := range []string{"?pretty", "?pretty=true"} {
		code, body := do(t, "GET", base+"/"+q, "", nil)
		if code != 200 {
			t.Fatalf("%s code=%d", q, code)
		}
		if !strings.Contains(body, "\n  \"cluster_name\"") {
			t.Fatalf("%s body not indented: %s", q, body)
		}
	}
	// 不带 pretty 与 ?pretty=false 都应是紧凑单行
	for _, q := range []string{"", "?pretty=false"} {
		_, body := do(t, "GET", base+"/"+q, "", nil)
		if strings.Contains(body, "\n  \"cluster_name\"") {
			t.Fatalf("%q should be compact: %s", q, body)
		}
	}
	// 事件里应记录原始 query（能看到攻击者带了 pretty）
	if _, body := do(t, "GET", base+"/?pretty", "", nil); !strings.Contains(body, "cluster_name") {
		t.Fatalf("pretty response missing cluster_name: %s", body)
	}
}
