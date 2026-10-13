package elasticsearch

/*
Elasticsearch 蜜罐服务（TCP 9200，Elasticsearch REST API，JSON over HTTP）。

低交互策略：
  - 连接级 keep-alive 循环：用标准库解析 HTTP 请求（请求行/首部/body），一个连接上可
    连续处理多个请求（ES 客户端、curl 都会复用连接），空闲超时后关闭。
  - 响应为手写 JSON（不引入第三方依赖），覆盖攻击者最常打的端点：
    GET /（集群信息）、_cluster/health、_nodes、_cat/*、_aliases、_search/_count、
    _bulk/_msearch，以及索引的增删改查与 _mapping/_settings。
  - 版本指纹不写死：yaml 只配 version 一个号，lucene_version / build_date /
    兼容性下限 / index.created 等附属字段按「yaml 覆盖 > 档案表(6/7/8/9) > 按不变量
    推导」取得，表里没有的新大版本也能自动给出配套值，不会出现"ES 9 配 Lucene 8"的违和组合。
  - 真存真取：PUT/POST <index>/_doc 写入的文档真实入库，后续 GET _doc/<id>、_search、
    _cat/indices、_count 都能看到，自洽难识别；DELETE 索引/文档同样生效。
    _bulk 按 NDJSON 逐条解析并真实执行 index/create/update/delete。
  - 无认证：不校验任何凭证，Authorization 头原样落事件（暴露未授权访问与凭证试探）。
  - _search 的 DSL body 是核心情报：script_fields 里的脚本（Groovy/MVEL 等 RCE 利用，
    如 CVE-2015-1427）会被单独提取成 es.script_* 字段；_reindex/_snapshot 等
    数据外传链路也会完整落 es.body。
  - 未知端点回 ES 风格 404 JSON（index_not_found_exception 等），保持指纹一致。
  - 事件 es-connect / es-request / es-close；es-request 含 method/url/path/query/
    index/action/doc_id/user-agent/content-type/authorization/body 与 script_*，
    均带 session-id(xid)。
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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

const (
	defaultClusterName = "elasticsearch"
	defaultNodeName    = "node-1"
	defaultVersion     = "8.11.1"
	defaultTagline     = "You Know, for Search"

	// maxBody 单请求 body 上限 1MB，超出部分截断（防恶意超大报文占内存）。
	maxBody = 1 << 20
	// connIdleTimeout keep-alive 连接空闲多久后关闭。
	connIdleTimeout = 300 * time.Second
	// seedDocsPerIndex 每个预置索引填充的诱饵文档数。
	seedDocsPerIndex = 3
)

var (
	serviceName = "elasticsearch"
	_           = services.Register(serviceName, ElasticsearchServiceInit)
	// clusterUUID 进程级稳定，避免每次请求都变（真实集群的 uuid 是固定的）。
	clusterUUID = randomUUID()
)

func ElasticsearchServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   elasticsearchHandle,
		ServiceOptions: elasticsearchConfig{store: newESStore()},
	}
}

// elasticsearchConfig 协议专属配置。各项留空均回退内置默认值。
type elasticsearchConfig struct {
	store       *esStore
	ClusterName string   `mapstructure:"cluster_name"`
	NodeName    string   `mapstructure:"node_name"`
	Version     string   `mapstructure:"version"`
	Tagline     string   `mapstructure:"tagline"`
	Indices     []string `mapstructure:"indices"`

	// 版本档案覆盖项（一般不用配）。不填时按 version 的大版本查内置档案表，
	// 表里没有的大版本再按不变量推导；只有要精确伪装某个具体构建时才需要显式指定。
	LuceneVersion         string `mapstructure:"lucene_version"`
	BuildDate             string `mapstructure:"build_date"`
	MinWireCompatVersion  string `mapstructure:"minimum_wire_compatibility_version"`
	MinIndexCompatVersion string `mapstructure:"minimum_index_compatibility_version"`
}

// versionProfileOf 按「yaml 覆盖 > 内置档案表 > 不变量推导」取版本档案。
func (c elasticsearchConfig) versionProfileOf() esVersionProfile {
	p := versionProfile(c.version())
	if c.LuceneVersion != "" {
		p.lucene = c.LuceneVersion
	}
	if c.BuildDate != "" {
		p.buildDate = c.BuildDate
	}
	if c.MinWireCompatVersion != "" {
		p.minWireCompat = c.MinWireCompatVersion
	}
	if c.MinIndexCompatVersion != "" {
		p.minIndexCompat = c.MinIndexCompatVersion
	}
	return p
}

func (c elasticsearchConfig) clusterName() string {
	if c.ClusterName != "" {
		return c.ClusterName
	}
	return defaultClusterName
}

func (c elasticsearchConfig) nodeName() string {
	if c.NodeName != "" {
		return c.NodeName
	}
	return defaultNodeName
}

func (c elasticsearchConfig) version() string {
	if c.Version != "" {
		return c.Version
	}
	return defaultVersion
}

func (c elasticsearchConfig) tagline() string {
	if c.Tagline != "" {
		return c.Tagline
	}
	return defaultTagline
}

// ---- 数据存储（index -> id -> doc，真存真取）----

type esDoc struct {
	source  map[string]interface{}
	version int
	seqNo   int
}

type esIndex struct {
	docs    map[string]*esDoc
	docSeq  int
	created time.Time
}

type esStore struct {
	mu      sync.Mutex
	indices map[string]*esIndex
	seq     int
	seeded  bool
}

func newESStore() *esStore {
	return &esStore{indices: make(map[string]*esIndex)}
}

// ensureSeeded 按配置把预置索引填入 store（仅首次生效，需持锁调用）。
func (s *esStore) ensureSeeded(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seeded {
		return
	}
	s.seeded = true
	for _, n := range names {
		if n == "" {
			continue
		}
		s.createIndexLocked(n)
		s.seedIndexLocked(n)
	}
}

// createIndexLocked 创建空索引（已存在则原样返回）。诱饵文档只在配置的预置索引里填充，
// 这样攻击者自己 PUT 建的索引是空的，与真实 ES 行为一致，也不会和它的文档 id 撞上。
func (s *esStore) createIndexLocked(name string) *esIndex {
	if idx, ok := s.indices[name]; ok {
		return idx
	}
	idx := &esIndex{docs: make(map[string]*esDoc), created: time.Now()}
	s.indices[name] = idx
	return idx
}

// seedIndexLocked 往索引里填诱饵文档（需持锁调用）。
func (s *esStore) seedIndexLocked(name string) {
	idx, ok := s.indices[name]
	if !ok {
		return
	}
	for i := 1; i <= seedDocsPerIndex; i++ {
		id := fmt.Sprintf("%d", i)
		if _, exists := idx.docs[id]; exists {
			continue
		}
		s.seq++
		idx.docs[id] = &esDoc{source: seedDoc(name, i), version: 1, seqNo: s.seq}
		idx.docSeq++
	}
}

func (s *esStore) hasIndex(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.indices[name]
	return ok
}

func (s *esStore) createIndex(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.indices[name]; ok {
		return false
	}
	s.createIndexLocked(name)
	return true
}

// deleteIndex 删除索引，返回是否本来存在。
func (s *esStore) deleteIndex(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.indices[name]; !ok {
		return false
	}
	delete(s.indices, name)
	return true
}

// putDoc 写入文档。id 为空则自动生成；返回 (最终 id, 是否新建, version, seqNo)。
func (s *esStore) putDoc(index, id string, source map[string]interface{}) (string, bool, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indices[index]
	if !ok {
		idx = s.createIndexLocked(index)
	}
	created := false
	if id == "" {
		idx.docSeq++
		id = fmt.Sprintf("%s-%d", xid.New().String(), idx.docSeq)
		created = true
	} else if _, exists := idx.docs[id]; !exists {
		created = true
	}
	s.seq++
	ver := 1
	if old, exists := idx.docs[id]; exists {
		ver = old.version + 1
	}
	idx.docs[id] = &esDoc{source: source, version: ver, seqNo: s.seq}
	return id, created, ver, s.seq
}

// updateDoc 合并 doc 字段到已有文档；文档不存在则新建。
func (s *esStore) updateDoc(index, id string, partial map[string]interface{}) (bool, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indices[index]
	if !ok {
		idx = s.createIndexLocked(index)
	}
	s.seq++
	ver := 1
	created := false
	if old, exists := idx.docs[id]; exists {
		ver = old.version + 1
		for k, v := range partial {
			old.source[k] = v
		}
		old.version = ver
		old.seqNo = s.seq
	} else {
		created = true
		idx.docs[id] = &esDoc{source: partial, version: ver, seqNo: s.seq}
	}
	return created, ver, s.seq
}

func (s *esStore) getDoc(index, id string) (map[string]interface{}, int, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indices[index]
	if !ok {
		return nil, 0, 0, false
	}
	d, ok := idx.docs[id]
	if !ok {
		return nil, 0, 0, false
	}
	return d.source, d.version, d.seqNo, true
}

func (s *esStore) deleteDoc(index, id string) (int, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indices[index]
	if !ok {
		return 0, 0, false
	}
	d, ok := idx.docs[id]
	if !ok {
		return 0, 0, false
	}
	delete(idx.docs, id)
	return d.version, d.seqNo, true
}

func (s *esStore) docCount(index string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indices[index]
	if !ok {
		return 0
	}
	return len(idx.docs)
}

func (s *esStore) totalDocs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, idx := range s.indices {
		n += len(idx.docs)
	}
	return n
}

// indexNames 返回排序后的索引名，保证 _cat 输出稳定。
func (s *esStore) indexNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.indices))
	for n := range s.indices {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// catIndices 生成 _cat/indices 的文本表格（列宽固定，便于阅读）。
func (s *esStore) catIndices() string {
	names := s.indexNames()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-6s %-6s %-20s %-24s %3s %3s %11s %12s %11s %14s\n",
		"health", "status", "index", "uuid", "pri", "rep", "docs.count", "docs.deleted", "store.size", "pri.store.size"))
	for _, n := range names {
		docs := s.docCount(n)
		store := fmt.Sprintf("%.1fkb", float64(docs)*256/1024)
		b.WriteString(fmt.Sprintf("%-6s %-6s %-20s %-24s %3d %3d %11d %12d %11s %14s\n",
			"green", "open", n, randomUUID(), 1, 1, docs, 0, store, store))
	}
	return b.String()
}

// searchHits 返回指定索引（空 = 全部）的命中列表，按索引名+id 排序。
func (s *esStore) searchHits(index string) []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	type row struct {
		idx, id string
		doc     *esDoc
	}
	rows := make([]row, 0)
	if index != "" {
		idx, ok := s.indices[index]
		if !ok {
			return nil
		}
		for id, d := range idx.docs {
			rows = append(rows, row{index, id, d})
		}
	} else {
		names := make([]string, 0, len(s.indices))
		for n := range s.indices {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			ids := make([]string, 0, len(s.indices[n].docs))
			for id := range s.indices[n].docs {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				rows = append(rows, row{n, id, s.indices[n].docs[id]})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].idx != rows[j].idx {
			return rows[i].idx < rows[j].idx
		}
		return rows[i].id < rows[j].id
	})
	hits := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		hits = append(hits, map[string]interface{}{
			"_index":  r.idx,
			"_type":   "_doc",
			"_id":     r.id,
			"_score":  1.0,
			"_source": r.doc.source,
		})
	}
	return hits
}

// seedDoc 生成预置索引的诱饵文档（看起来像业务数据，诱使攻击者继续翻）。
func seedDoc(index string, n int) map[string]interface{} {
	return map[string]interface{}{
		"@timestamp": time.Now().UTC().Add(-time.Duration(n) * time.Hour).Format(time.RFC3339),
		"index":      index,
		"id":         n,
		"name":       fmt.Sprintf("user-%d", n),
		"email":      fmt.Sprintf("user%d@example.com", n),
		"message":    "seeded sample document",
	}
}

// ---- 连接处理 ----

func elasticsearchHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(elasticsearchConfig)
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
			go handleConn(conn, service, cfg)
		}
	}
}

func handleConn(conn net.Conn, service *services.Service, cfg elasticsearchConfig) {
	defer conn.Close()
	baseOptions := service.BaseOptions
	cfg.store.ensureSeeded(cfg.Indices)

	id := xid.New()
	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "es-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":        baseOptions.Protocol,
		"application":     baseOptions.Application,
		"es.session-id":   id.String(),
		"es.cluster_name": cfg.clusterName(),
	}))

	pushClose := func() {
		event.EventPush(event.NewEvent(serviceName, "es-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":      baseOptions.Protocol,
			"application":   baseOptions.Application,
			"es.session-id": id.String(),
		}))
	}

	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(connIdleTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			// EOF / 解析失败都意味着这个连接结束
			pushClose()
			return
		}
		body := readRequestBody(req)
		handleRequest(conn, req, service, cfg, id, srcAddr, dstAddr, body)
	}
}

// readRequestBody 读取请求体（上限 maxBody，超出截断）并排空残余以保证 keep-alive。
func readRequestBody(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	defer req.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	if len(data) > maxBody {
		data = data[:maxBody]
	}
	_, _ = io.Copy(io.Discard, req.Body)
	return data
}

func handleRequest(conn net.Conn, req *http.Request, service *services.Service, cfg elasticsearchConfig,
	id xid.ID, srcAddr, dstAddr common.Addr, body []byte) {
	baseOptions := service.BaseOptions
	segs := splitPath(req.URL.Path)
	method := strings.ToUpper(req.Method)
	index, docID, action := classifyTarget(method, segs)

	details := map[string]interface{}{
		"protocol":          baseOptions.Protocol,
		"application":       baseOptions.Application,
		"es.session-id":     id.String(),
		"es.method":         req.Method,
		"es.url":            req.URL.String(),
		"es.path":           req.URL.Path,
		"es.query":          req.URL.RawQuery,
		"es.action":         action,
		"es.user_agent":     req.UserAgent(),
		"es.content_type":   req.Header.Get("Content-Type"),
		"es.content_length": req.ContentLength,
		"es.host":           req.Host,
		"es.referer":        req.Header.Get("Referer"),
		"es.body":           string(body),
	}
	if index != "" {
		details["es.index"] = index
	}
	if docID != "" {
		details["es.doc_id"] = docID
	}
	if auth := req.Header.Get("Authorization"); auth != "" {
		details["es.authorization"] = auth
		if user, pass, ok := parseBasicAuth(auth); ok {
			details["es.auth_username"] = user
			details["es.auth_password"] = pass
		}
	}
	// DSL 里的脚本是 RCE 利用（如 CVE-2015-1427 Groovy）的核心载荷，单独提取
	for k, v := range extractScripts(body) {
		details["es.script_"+k] = v
	}
	event.EventPush(event.NewEvent(serviceName, "es-request", srcAddr, dstAddr, details))

	route(conn, req, cfg, method, segs, body)
}

// ---- 路由 ----

func route(conn net.Conn, req *http.Request, cfg elasticsearchConfig, method string, segs []string, body []byte) {
	if len(segs) == 0 {
		respondJSON(conn, req, http.StatusOK, rootInfo(cfg))
		return
	}

	head := segs[0]
	if strings.HasPrefix(head, "_") {
		switch head {
		case "_cluster":
			handleCluster(conn, req, cfg, segs)
		case "_cat":
			handleCat(conn, req, cfg, method, segs)
		case "_nodes":
			respondJSON(conn, req, http.StatusOK, nodesInfo(cfg))
		case "_aliases":
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{})
		case "_search", "_msearch":
			handleSearch(conn, req, cfg, "", body)
		case "_count":
			respondJSON(conn, req, http.StatusOK, countResponse(cfg.store.totalDocs()))
		case "_bulk":
			handleBulk(conn, req, cfg, body)
		case "_all":
			handleAll(conn, req, cfg, method, segs, body)
		case "_stats":
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{
				"_shards": shardInfo(1), "_all": allStats(cfg),
			})
		default:
			respondError(conn, req, http.StatusNotFound, "illegal_argument_exception",
				fmt.Sprintf("no handler found for uri [%s] and method [%s]", req.URL.Path, req.Method))
		}
		return
	}

	handleIndexPath(conn, req, cfg, method, segs, body)
}

func handleCluster(conn net.Conn, req *http.Request, cfg elasticsearchConfig, segs []string) {
	if len(segs) >= 2 {
		switch segs[1] {
		case "health":
			respondJSON(conn, req, http.StatusOK, healthInfo(cfg))
			return
		case "state":
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{
				"cluster_name": cfg.clusterName(),
				"cluster_uuid": clusterUUID,
				"version":      1,
				"state_uuid":   randomUUID(),
				"master_node":  cfg.nodeName(),
				"status":       "green",
			})
			return
		case "settings", "stats":
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{
				"cluster_name": cfg.clusterName(),
				"cluster_uuid": clusterUUID,
				"status":       "green",
			})
			return
		}
	}
	respondJSON(conn, req, http.StatusOK, healthInfo(cfg))
}

func handleCat(conn net.Conn, req *http.Request, cfg elasticsearchConfig, method string, segs []string) {
	what := ""
	if len(segs) >= 2 {
		what = segs[1]
	}
	switch what {
	case "indices", "shards":
		respondText(conn, req, http.StatusOK, cfg.store.catIndices())
	case "nodes":
		respondText(conn, req, http.StatusOK, fmt.Sprintf(
			"ip        heap.percent ram.percent cpu load_1m load_5m load_15m node.role master name\n"+
				"127.0.0.1           12          45   2    0.12    0.15     0.09 dim       *      %s\n", cfg.nodeName()))
	case "health":
		respondText(conn, req, http.StatusOK, fmt.Sprintf(
			"epoch      timestamp cluster            status node.total node.data shards pri relo init unassign pending_task\n"+
				"1600000000 00:00:00  %s green   1         1         3     3    0    0        0             0\n", cfg.clusterName()))
	case "aliases":
		respondText(conn, req, http.StatusOK, "")
	case "count":
		respondText(conn, req, http.StatusOK, fmt.Sprintf("epoch      timestamp count\n1600000000 00:00:00  %d\n", cfg.store.totalDocs()))
	default:
		respondText(conn, req, http.StatusOK, "")
	}
}

func handleAll(conn net.Conn, req *http.Request, cfg elasticsearchConfig, method string, segs []string, body []byte) {
	// /_all/_settings、/_all/_mapping、/_all/_search 等
	if len(segs) >= 2 {
		switch segs[1] {
		case "_settings":
			respondJSON(conn, req, http.StatusOK, allSettings(cfg))
			return
		case "_mapping":
			respondJSON(conn, req, http.StatusOK, allMapping(cfg))
			return
		case "_search":
			handleSearch(conn, req, cfg, "", body)
			return
		}
	}
	respondError(conn, req, http.StatusNotFound, "illegal_argument_exception",
		fmt.Sprintf("no handler found for uri [%s] and method [%s]", req.URL.Path, req.Method))
}

func handleIndexPath(conn net.Conn, req *http.Request, cfg elasticsearchConfig, method string, segs []string, body []byte) {
	index := segs[0]

	// /<index>
	if len(segs) == 1 {
		switch method {
		case "PUT", "POST":
			created := cfg.store.createIndex(index)
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{
				"acknowledged":        true,
				"shards_acknowledged": true,
				"index":               index,
			})
			_ = created
		case "DELETE":
			existed := cfg.store.deleteIndex(index)
			if !existed {
				respondIndexNotFound(conn, req, index)
				return
			}
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{"acknowledged": true})
		case "HEAD":
			if cfg.store.hasIndex(index) {
				respondEmpty(conn, req, http.StatusOK)
			} else {
				respondEmpty(conn, req, http.StatusNotFound)
			}
		default:
			respondError(conn, req, http.StatusMethodNotAllowed, "illegal_argument_exception",
				fmt.Sprintf("method [%s] not allowed for uri [%s]", req.Method, req.URL.Path))
		}
		return
	}

	sub := segs[1]
	docID := ""
	if len(segs) >= 3 {
		docID = segs[2]
	}

	switch sub {
	case "_search", "_delete_by_query", "_update_by_query":
		handleSearch(conn, req, cfg, index, body)
	case "_count":
		if !cfg.store.hasIndex(index) {
			respondIndexNotFound(conn, req, index)
			return
		}
		respondJSON(conn, req, http.StatusOK, countResponse(cfg.store.docCount(index)))
	case "_doc", "_create", "_update":
		handleDoc(conn, req, cfg, method, index, docID, sub, body)
	case "_source":
		handleSource(conn, req, cfg, index, docID)
	case "_mapping":
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			index: map[string]interface{}{
				"mappings": map[string]interface{}{
					"dynamic":    true,
					"properties": map[string]interface{}{},
				},
			},
		})
	case "_settings":
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			index: map[string]interface{}{
				"settings": indexSettings(cfg, index),
			},
		})
	case "_alias", "_aliases":
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{})
	case "_refresh", "_flush", "_forcemerge":
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"_shards": shardInfo(1),
		})
	case "_bulk":
		handleBulk(conn, req, cfg, body)
	default:
		respondError(conn, req, http.StatusNotFound, "illegal_argument_exception",
			fmt.Sprintf("no handler found for uri [%s] and method [%s]", req.URL.Path, req.Method))
	}
}

func handleDoc(conn net.Conn, req *http.Request, cfg elasticsearchConfig, method, index, docID, sub string, body []byte) {
	switch method {
	case "PUT", "POST":
		source := parseJSONObject(body)
		if source == nil {
			respondError(conn, req, http.StatusBadRequest, "parse_exception",
				"request body is not a valid JSON object")
			return
		}
		if sub == "_update" && docID != "" {
			// _update 的 body 形如 {"doc": {...}}，合并到已有文档
			partial := source
			if d, ok := source["doc"].(map[string]interface{}); ok {
				partial = d
			}
			_, ver, seq := cfg.store.updateDoc(index, docID, partial)
			respondJSON(conn, req, http.StatusOK, docWriteResponse(index, docID, ver, seq, "updated"))
			return
		}
		id, created, ver, seq := cfg.store.putDoc(index, docID, source)
		result := "created"
		if !created {
			result = "updated"
		}
		respondJSON(conn, req, http.StatusOK, docWriteResponse(index, id, ver, seq, result))
	case "GET":
		if !cfg.store.hasIndex(index) {
			respondIndexNotFound(conn, req, index)
			return
		}
		if docID == "" {
			respondError(conn, req, http.StatusBadRequest, "illegal_argument_exception",
				"an id is required for GET /<index>/_doc/<id>")
			return
		}
		src, ver, seq, found := cfg.store.getDoc(index, docID)
		if !found {
			respondJSON(conn, req, http.StatusNotFound, map[string]interface{}{
				"_index": index, "_type": "_doc", "_id": docID, "found": false,
			})
			return
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"_index": index, "_type": "_doc", "_id": docID,
			"_version": ver, "_seq_no": seq, "_primary_term": 1, "found": true,
			"_source": src,
		})
	case "DELETE":
		if !cfg.store.hasIndex(index) {
			respondIndexNotFound(conn, req, index)
			return
		}
		ver, seq, found := cfg.store.deleteDoc(index, docID)
		if !found {
			respondJSON(conn, req, http.StatusNotFound, map[string]interface{}{
				"_index": index, "_type": "_doc", "_id": docID, "found": false,
			})
			return
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"_index": index, "_type": "_doc", "_id": docID,
			"_version": ver + 1, "_seq_no": seq, "_primary_term": 1, "result": "deleted",
			"_shards": shardInfo(2),
		})
	default:
		respondError(conn, req, http.StatusMethodNotAllowed, "illegal_argument_exception",
			fmt.Sprintf("method [%s] not allowed for uri [%s]", req.Method, req.URL.Path))
	}
}

func handleSource(conn net.Conn, req *http.Request, cfg elasticsearchConfig, index, docID string) {
	if req.Method != "GET" {
		respondError(conn, req, http.StatusMethodNotAllowed, "illegal_argument_exception",
			fmt.Sprintf("method [%s] not allowed for uri [%s]", req.Method, req.URL.Path))
		return
	}
	if !cfg.store.hasIndex(index) {
		respondIndexNotFound(conn, req, index)
		return
	}
	src, _, _, found := cfg.store.getDoc(index, docID)
	if !found {
		respondError(conn, req, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("document missing for [%s/_doc/%s]", index, docID))
		return
	}
	respondJSON(conn, req, http.StatusOK, src)
}

func handleSearch(conn net.Conn, req *http.Request, cfg elasticsearchConfig, index string, body []byte) {
	if index != "" && !cfg.store.hasIndex(index) {
		respondIndexNotFound(conn, req, index)
		return
	}
	hits := cfg.store.searchHits(index)
	respondJSON(conn, req, http.StatusOK, map[string]interface{}{
		"took":      2,
		"timed_out": false,
		"_shards":   shardInfo(1),
		"hits": map[string]interface{}{
			"total":     map[string]interface{}{"value": len(hits), "relation": "eq"},
			"max_score": 1.0,
			"hits":      hits,
		},
	})
}

// handleBulk 按 NDJSON 逐条解析并真实执行，响应同样为 NDJSON。
func handleBulk(conn net.Conn, req *http.Request, cfg elasticsearchConfig, body []byte) {
	items := make([]string, 0)
	lines := strings.Split(string(body), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var action map[string]map[string]interface{}
		if err := json.Unmarshal([]byte(line), &action); err != nil || len(action) != 1 {
			continue
		}
		for op, meta := range action {
			idx, _ := meta["_index"].(string)
			docID, _ := meta["_id"].(string)
			var source map[string]interface{}
			switch op {
			case "index", "create", "update":
				if i+1 < len(lines) {
					var doc map[string]interface{}
					if json.Unmarshal([]byte(strings.TrimSpace(lines[i+1])), &doc) == nil {
						i++
						if op == "update" {
							if d, ok := doc["doc"].(map[string]interface{}); ok {
								source = d
							} else {
								source = doc
							}
						} else {
							source = doc
						}
					}
				}
			}

			switch op {
			case "index", "create":
				id, created, ver, seq := cfg.store.putDoc(idx, docID, source)
				result := "created"
				if !created {
					result = "updated"
				}
				items = append(items, bulkItemLine(op, idx, id, ver, seq, result, false))
			case "update":
				if docID == "" {
					items = append(items, bulkItemLine(op, idx, docID, 0, 0, "noop", true))
					continue
				}
				_, ver, seq := cfg.store.updateDoc(idx, docID, source)
				items = append(items, bulkItemLine(op, idx, docID, ver, seq, "updated", false))
			case "delete":
				ver, seq, found := cfg.store.deleteDoc(idx, docID)
				if !found {
					items = append(items, bulkItemLine(op, idx, docID, 0, 0, "not_found", true))
					continue
				}
				items = append(items, bulkItemLine(op, idx, docID, ver+1, seq, "deleted", false))
			default:
				// 未知动作，原样回显元信息
				items = append(items, bulkItemLine(op, idx, docID, 0, 0, "noop", true))
			}
		}
	}
	respondText(conn, req, http.StatusOK, strings.Join(items, "\n")+"\n")
}

func bulkItemLine(op, index, id string, ver, seq int, result string, hasErr bool) string {
	entry := map[string]interface{}{
		"_index": index, "_type": "_doc", "_id": id,
		"_version": ver, "result": result,
		"_shards":       shardInfo(2),
		"_seq_no":       seq,
		"_primary_term": 1,
		"status":        200,
	}
	if hasErr {
		entry["status"] = 404
	}
	data, err := json.Marshal(map[string]interface{}{op: entry})
	if err != nil {
		return ""
	}
	return string(data)
}

// ---- 响应构造 ----

// wantPretty 判断是否请求美化输出（?pretty 或 ?pretty=true；?pretty=false 关）。
// curl / kibana / head 插件等 ES 客户端很常用这个参数。
func wantPretty(req *http.Request) bool {
	q := req.URL.Query()
	if !q.Has("pretty") {
		return false
	}
	return !strings.EqualFold(q.Get("pretty"), "false")
}

func respondJSON(conn net.Conn, req *http.Request, status int, payload interface{}) {
	var (
		data []byte
		err  error
	)
	if wantPretty(req) {
		data, err = json.MarshalIndent(payload, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	} else {
		data, err = json.Marshal(payload)
	}
	if err != nil {
		logger.Log.Debug(serviceName, " marshal error:", err)
		data = []byte(`{"error":{"type":"internal","reason":"response marshal failed"}}`)
		status = http.StatusInternalServerError
	}
	respond(conn, req, status, "application/json; charset=UTF-8", data)
}

func respondText(conn net.Conn, req *http.Request, status int, text string) {
	respond(conn, req, status, "text/plain; charset=UTF-8", []byte(text))
}

func respondEmpty(conn net.Conn, req *http.Request, status int) {
	respond(conn, req, status, "application/json; charset=UTF-8", nil)
}

func respond(conn net.Conn, req *http.Request, status int, contentType string, body []byte) {
	resp := http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Proto:         req.Proto,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		Header:        http.Header{},
		Body:          http.NoBody,
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", contentType)
	// HEAD 请求按 HTTP 语义只回状态行+首部，不回 body
	if req.Method != "HEAD" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := resp.Write(conn); err != nil {
		logger.Log.Debug(serviceName, " write error:", err)
	}
}

func respondError(conn net.Conn, req *http.Request, status int, errType, reason string) {
	rootCause := map[string]interface{}{
		"type":   errType,
		"reason": reason,
	}
	respondJSON(conn, req, status, map[string]interface{}{
		"error":  rootCause,
		"status": status,
	})
}

func respondIndexNotFound(conn net.Conn, req *http.Request, index string) {
	reason := fmt.Sprintf("no such index [%s]", index)
	respondJSON(conn, req, http.StatusNotFound, map[string]interface{}{
		"error": map[string]interface{}{
			"root_cause": []map[string]interface{}{{
				"type": "index_not_found_exception", "reason": reason,
				"index": index, "resource.type": "index_or_alias", "resource.id": index,
				"index_uuid": "_na_",
			}},
			"type": "index_not_found_exception", "reason": reason,
			"index": index, "resource.type": "index_or_alias", "resource.id": index,
			"index_uuid": "_na_",
		},
		"status": 404,
	})
}

// ---- 响应体片段 ----

// esVersionProfile 描述某个 ES 大版本对应的 Lucene 版本、构建时间与兼容性下限。
// 这些字段必须跟 version.number 对得上：只换 version 不换它们会立刻露馅。
// 取值优先级：yaml 显式覆盖 > esVersionProfiles 档案表（已知大版本的精确值）>
// deriveProfile 按不变量推导（表里没有的大版本）。
type esVersionProfile struct {
	lucene         string
	buildDate      string
	minWireCompat  string
	minIndexCompat string
}

// esVersionProfiles 已知大版本的档案（精确值）。
// 表不需要穷尽所有版本：下面有 deriveProfile 按不变量兜底，新大版本（9、10…）
// 只有在要精确到某个具体构建时才值得加进来。
var esVersionProfiles = map[int]esVersionProfile{
	6: {
		lucene:         "7.7.3",
		buildDate:      "2020-05-15T09:41:36.784Z",
		minWireCompat:  "5.6.0",
		minIndexCompat: "5.0.0",
	},
	7: {
		lucene:         "8.11.1",
		buildDate:      "2022-09-23T23:32:32.893159473Z",
		minWireCompat:  "6.8.0",
		minIndexCompat: "6.0.0-beta1",
	},
	8: {
		lucene:         "9.8.0",
		buildDate:      "2023-11-04T10:04:57.602455096Z",
		minWireCompat:  "7.17.0",
		minIndexCompat: "7.0.0",
	},
	9: {
		lucene:         "10.1.0",
		buildDate:      "2025-04-15T09:32:11.831021935Z",
		minWireCompat:  "8.18.0",
		minIndexCompat: "8.0.0",
	},
}

// parseVersion 解析 "8.11.1" -> (8, 11, 1)；非法段按 0 处理。
func parseVersion(v string) (major, minor, patch int) {
	parts := strings.SplitN(strings.TrimSpace(v), ".", 3)
	atoi := func(s string) int {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return 0
		}
		return n
	}
	if len(parts) > 0 {
		major = atoi(parts[0])
	}
	if len(parts) > 1 {
		minor = atoi(parts[1])
	}
	if len(parts) > 2 {
		patch = atoi(parts[2])
	}
	return major, minor, patch
}

// deriveProfile 为档案表里没有的大版本按 ES 的一贯不变量推导一份"说得通"的档案：
//   - Lucene 大版本始终 = ES 大版本 + 1（6→7、7→8、8→9、9→10），这是最关键的守恒关系；
//   - minimum_index_compatibility_version 始终 = 上一个 ES 大版本的 .0.0（8→7.0.0、7→6.0.0）；
//   - minimum_wire_compatibility_version 取上一个 ES 大版本的末位小版本，统一按 .17.0 估
//     （8.x 的真实下限正是 7.17.0；7.x 的 6.8.0 由档案表精确给出）；
//   - build_date 无法从版本号推导，回落默认档案的值（该字段信号价值最低）。
//
// 推导值不保证与官方构建完全一致，但足以保证"这个版本配这套附属字段"不违和；
// 需要精确伪装某个具体构建时，用 yaml 的覆盖字段显式指定。
func deriveProfile(major, minor int) esVersionProfile {
	def := esVersionProfiles[defaultProfileMajor()]
	return esVersionProfile{
		lucene:         fmt.Sprintf("%d.%d.1", major+1, minor),
		buildDate:      def.buildDate,
		minWireCompat:  fmt.Sprintf("%d.17.0", major-1),
		minIndexCompat: fmt.Sprintf("%d.0.0", major-1),
	}
}

// defaultProfileMajor 返回默认版本的大版本号（推导时的兜底档位）。
func defaultProfileMajor() int {
	major, _, _ := parseVersion(defaultVersion)
	return major
}

// versionProfile 取版本档案：先查表，表里没有的大版本按不变量推导；
// 版本号非法时回落到默认版本的档案。
func versionProfile(v string) esVersionProfile {
	major, minor, _ := parseVersion(v)
	if major <= 0 {
		major, minor, _ = parseVersion(defaultVersion)
	}
	if p, ok := esVersionProfiles[major]; ok {
		return p
	}
	return deriveProfile(major, minor)
}

// buildHash 由版本号确定性派生 40 位十六进制串。真实 ES 的 build_hash 是 git commit，
// 同一版本的构建是固定的，所以这里也必须稳定（不能每次随机）。
func buildHash(ver string) string {
	sum := sha1.Sum([]byte("potagent-es-" + ver))
	return hex.EncodeToString(sum[:])
}

// indexCreated 生成 index.settings.version.created（形如 7.17.0 -> "7170099"）。
func indexCreated(ver string) string {
	major, minor, patch := parseVersion(ver)
	return fmt.Sprintf("%d%02d%02d99", major, minor, patch)
}

func rootInfo(cfg elasticsearchConfig) map[string]interface{} {
	ver := cfg.version()
	p := cfg.versionProfileOf()
	return map[string]interface{}{
		"name":         cfg.nodeName(),
		"cluster_name": cfg.clusterName(),
		"cluster_uuid": clusterUUID,
		"version": map[string]interface{}{
			"number":                              ver,
			"build_flavor":                        "default",
			"build_type":                          "docker",
			"build_hash":                          buildHash(ver),
			"build_date":                          p.buildDate,
			"build_snapshot":                      false,
			"lucene_version":                      p.lucene,
			"minimum_wire_compatibility_version":  p.minWireCompat,
			"minimum_index_compatibility_version": p.minIndexCompat,
		},
		"tagline": cfg.tagline(),
	}
}

func healthInfo(cfg elasticsearchConfig) map[string]interface{} {
	names := cfg.store.indexNames()
	shards := len(names)
	if shards == 0 {
		shards = 1
	}
	return map[string]interface{}{
		"cluster_name":                     cfg.clusterName(),
		"status":                           "green",
		"timed_out":                        false,
		"number_of_nodes":                  1,
		"number_of_data_nodes":             1,
		"active_primary_shards":            shards,
		"active_shards":                    shards,
		"relocating_shards":                0,
		"initializing_shards":              0,
		"unassigned_shards":                0,
		"delayed_unassigned_shards":        0,
		"number_of_pending_tasks":          0,
		"number_of_in_flight_fetch":        0,
		"task_max_waiting_in_queue_millis": 0,
		"active_shards_percent_as_number":  100.0,
	}
}

func nodesInfo(cfg elasticsearchConfig) map[string]interface{} {
	return map[string]interface{}{
		"_nodes":       map[string]interface{}{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": cfg.clusterName(),
		"nodes": map[string]interface{}{
			randomUUID(): map[string]interface{}{
				"name":              cfg.nodeName(),
				"transport_address": "127.0.0.1:9300",
				"host":              "127.0.0.1",
				"ip":                "127.0.0.1",
				"version":           cfg.version(),
				"build_flavor":      "default",
				"build_type":        "docker",
				"roles":             []string{"master", "data", "ingest"},
			},
		},
	}
}

func allStats(cfg elasticsearchConfig) map[string]interface{} {
	return map[string]interface{}{
		"primaries": map[string]interface{}{"docs": map[string]interface{}{"count": cfg.store.totalDocs()}},
		"total":     map[string]interface{}{"docs": map[string]interface{}{"count": cfg.store.totalDocs()}},
	}
}

func allSettings(cfg elasticsearchConfig) map[string]interface{} {
	out := map[string]interface{}{}
	for _, n := range cfg.store.indexNames() {
		out[n] = map[string]interface{}{"settings": indexSettings(cfg, n)}
	}
	return out
}

func allMapping(cfg elasticsearchConfig) map[string]interface{} {
	out := map[string]interface{}{}
	for _, n := range cfg.store.indexNames() {
		out[n] = map[string]interface{}{
			"mappings": map[string]interface{}{"dynamic": true, "properties": map[string]interface{}{}},
		}
	}
	return out
}

// indexSettings 返回单个索引的 settings。created 由 version 派生，
// provided_name 用真实索引名（真实 ES 回显创建时给的名字）。
func indexSettings(cfg elasticsearchConfig, name string) map[string]interface{} {
	return map[string]interface{}{
		"index": map[string]interface{}{
			"number_of_shards":   "1",
			"number_of_replicas": "1",
			"version": map[string]interface{}{
				"created": indexCreated(cfg.version()),
			},
			"provided_name": name,
		},
	}
}

func shardInfo(total int) map[string]interface{} {
	successful := total
	if successful > 1 {
		successful = 1
	}
	return map[string]interface{}{
		"total": total, "successful": successful, "skipped": 0, "failed": 0,
	}
}

func countResponse(n int) map[string]interface{} {
	return map[string]interface{}{
		"count":   n,
		"_shards": shardInfo(1),
	}
}

func docWriteResponse(index, id string, ver, seq int, result string) map[string]interface{} {
	return map[string]interface{}{
		"_index": index, "_type": "_doc", "_id": id,
		"_version": ver, "result": result,
		"_shards": shardInfo(2),
		"_seq_no": seq, "_primary_term": 1,
	}
}

// ---- 解析辅助 ----

// splitPath 把 URL 路径切成段（去掉首尾 /），"/" 返回空。
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// classifyTarget 推断 index / doc_id / action，用于事件字段归类。
func classifyTarget(method string, segs []string) (index, docID, action string) {
	if len(segs) == 0 {
		return "", "", "cluster_info"
	}
	head := segs[0]
	if strings.HasPrefix(head, "_") {
		switch head {
		case "_cluster":
			if len(segs) >= 2 {
				return "", "", "cluster_" + segs[1]
			}
			return "", "", "cluster_info"
		case "_cat":
			if len(segs) >= 2 {
				return "", "", "cat_" + segs[1]
			}
			return "", "", "cat"
		case "_nodes":
			return "", "", "nodes"
		case "_search":
			return "", "", "search"
		case "_count":
			return "", "", "count"
		case "_bulk":
			return "", "", "bulk"
		case "_msearch":
			return "", "", "msearch"
		case "_aliases", "_all":
			return "", "", head
		default:
			return "", "", "api_" + strings.TrimPrefix(head, "_")
		}
	}

	index = head
	if len(segs) == 1 {
		switch method {
		case "PUT", "POST":
			return index, "", "create_index"
		case "DELETE":
			return index, "", "delete_index"
		case "HEAD":
			return index, "", "head_index"
		default:
			return index, "", "index_root"
		}
	}

	sub := segs[1]
	if len(segs) >= 3 {
		docID = segs[2]
	}
	switch sub {
	case "_search", "_delete_by_query", "_update_by_query":
		return index, "", "search"
	case "_count":
		return index, "", "count"
	case "_doc":
		switch method {
		case "GET":
			return index, docID, "get_doc"
		case "DELETE":
			return index, docID, "delete_doc"
		default:
			return index, docID, "index_doc"
		}
	case "_create":
		return index, docID, "create_doc"
	case "_update":
		return index, docID, "update_doc"
	case "_source":
		return index, docID, "get_source"
	case "_mapping":
		return index, "", "mapping"
	case "_settings":
		return index, "", "settings"
	default:
		return index, docID, "index_" + strings.TrimPrefix(sub, "_")
	}
}

func parseJSONObject(body []byte) map[string]interface{} {
	if len(body) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m
}

// parseBasicAuth 解析 Authorization: Basic base64(user:pass)。
func parseBasicAuth(auth string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	cred := string(raw)
	i := strings.IndexByte(cred, ':')
	if i < 0 {
		return cred, "", true
	}
	return cred[:i], cred[i+1:], true
}

// extractScripts 从 DSL body 里递归提取脚本内容（script/inline/source 字段），
// 这是 CVE-2015-1427 一类 RCE 利用的载荷所在。返回值直接并入事件 details。
// 注意 script 的值既可能是字符串，也可能是 {"lang":..,"inline"/"source":..} 对象，
// 两种形态都要能取到载荷。
func extractScripts(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 || !bytes.Contains(body, []byte("script")) {
		return out
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return out
	}
	n := 0
	var walk func(node interface{}, depth int)
	walk = func(node interface{}, depth int) {
		if depth > 12 || n >= 8 {
			return
		}
		switch t := node.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				switch strings.ToLower(k) {
				case "script", "inline", "source":
					if s, ok := t[k].(string); ok && s != "" {
						n++
						out[fmt.Sprintf("%d", n)] = s
						continue
					}
					// 值是对象（{"lang":..,"inline":..}）时继续下钻
					walk(t[k], depth+1)
				default:
					walk(t[k], depth+1)
				}
			}
		case []interface{}:
			for _, item := range t {
				walk(item, depth+1)
			}
		}
	}
	walk(v, 0)
	return out
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
