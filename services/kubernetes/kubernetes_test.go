package kubernetes

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"potAgent/common"
	"potAgent/global"
	"potAgent/services"
)

// ---- 测试基建 ----

func testConfig() kubernetesConfig {
	return kubernetesConfig{
		store:        newK8sStore(),
		Version:      "v1.28.4",
		IdleTimeoutS: 30,
	}
}

// startTestServer 起一个 127.0.0.1 随机端口的 HTTPS 实例（与主流程一致走 handleConn）。
func startTestServer(t *testing.T, cfg kubernetesConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := &services.Service{
		BaseOptions:    global.ServiceBaseConfig{Protocol: "kubernetes", Application: "kubernetes"},
		ServiceOptions: cfg,
	}
	cert, err := common.LoadOrGenCert("", "", "kubernetes")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := common.NewServerTLSConfig(cert)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(c, svc, cfg, tlsConf)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

var testClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func do(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func doCT(t *testing.T, method, url, contentType, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func decode(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return m
}

func itemsOf(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	m := decode(t, body)
	raw, ok := m["items"].([]interface{})
	if !ok {
		t.Fatalf("no items in %q", body)
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]interface{}))
	}
	return out
}

func meta(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	m, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("no metadata in %v", obj)
	}
	return m
}

func namesOf(t *testing.T, objs []map[string]interface{}) []string {
	t.Helper()
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, meta(t, o)["name"].(string))
	}
	return out
}

// ---- 版本与 discovery ----

func TestVersion(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()

	code, body := do(t, "GET", "https://"+addr+"/version", "")
	if code != 200 {
		t.Fatalf("version code=%d", code)
	}
	v := decode(t, body)
	// minor 必须是 "28"（不能是 "28.4"）
	if v["major"] != "1" || v["minor"] != "28" || v["gitVersion"] != "v1.28.4" {
		t.Fatalf("version=%v", v)
	}
	if v["platform"] != "linux/amd64" || v["compiler"] != "gc" || v["gitTreeState"] != "clean" {
		t.Fatalf("version=%v", v)
	}
}

func TestDiscovery(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	// /api
	code, body := do(t, "GET", base+"/api", "")
	if code != 200 {
		t.Fatalf("/api code=%d", code)
	}
	api := decode(t, body)
	if api["kind"] != "APIVersions" {
		t.Fatalf("/api=%v", api)
	}
	versions := api["versions"].([]interface{})
	if len(versions) != 1 || versions[0] != "v1" {
		t.Fatalf("/api versions=%v", versions)
	}

	// /api/v1
	code, body = do(t, "GET", base+"/api/v1", "")
	if code != 200 {
		t.Fatalf("/api/v1 code=%d", code)
	}
	list := decode(t, body)
	if list["kind"] != "APIResourceList" || list["groupVersion"] != "v1" {
		t.Fatalf("/api/v1=%v", list)
	}
	res := map[string]map[string]interface{}{}
	for _, r := range list["resources"].([]interface{}) {
		m := r.(map[string]interface{})
		res[m["name"].(string)] = m
	}
	for _, want := range []string{"pods", "pods/log", "services", "namespaces", "nodes", "configmaps", "secrets", "events", "persistentvolumes"} {
		if _, ok := res[want]; !ok {
			t.Fatalf("/api/v1 missing resource %q", want)
		}
	}
	if res["pods"]["namespaced"] != true || res["nodes"]["namespaced"] != false {
		t.Fatalf("namespaced flags wrong: %v / %v", res["pods"]["namespaced"], res["nodes"]["namespaced"])
	}
	if !strings.Contains(fmt.Sprint(res["pods"]["verbs"]), "watch") {
		t.Fatalf("pods verbs=%v", res["pods"]["verbs"])
	}

	// /apis
	code, body = do(t, "GET", base+"/apis", "")
	if code != 200 {
		t.Fatalf("/apis code=%d", code)
	}
	groups := map[string]bool{}
	for _, g := range decode(t, body)["groups"].([]interface{}) {
		groups[g.(map[string]interface{})["name"].(string)] = true
	}
	for _, want := range []string{"apps", "batch", "rbac.authorization.k8s.io", "authorization.k8s.io", "authentication.k8s.io"} {
		if !groups[want] {
			t.Fatalf("/apis missing group %q: %v", want, groups)
		}
	}

	// /apis/apps 与 /apis/apps/v1
	if code, body := do(t, "GET", base+"/apis/apps", ""); code != 200 {
		t.Fatalf("/apis/apps code=%d", code)
	} else if decode(t, body)["name"] != "apps" {
		t.Fatalf("/apis/apps=%v", decode(t, body))
	}
	code, body = do(t, "GET", base+"/apis/apps/v1", "")
	if code != 200 {
		t.Fatalf("/apis/apps/v1 code=%d", code)
	}
	ar := map[string]bool{}
	for _, r := range decode(t, body)["resources"].([]interface{}) {
		ar[r.(map[string]interface{})["name"].(string)] = true
	}
	for _, want := range []string{"deployments", "replicasets", "statefulsets", "daemonsets", "deployments/scale"} {
		if !ar[want] {
			t.Fatalf("/apis/apps/v1 missing %q", want)
		}
	}
}

// ---- 列表 / 单个对象 / 选择器 ----

func TestListsAndGet(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	// 命名空间
	_, body := do(t, "GET", base+"/api/v1/namespaces", "")
	nss := namesOf(t, itemsOf(t, body))
	for _, want := range []string{"default", "kube-system", "kube-public", "kube-node-lease"} {
		if !containsStr(nss, want) {
			t.Fatalf("namespaces=%v missing %q", nss, want)
		}
	}
	// 列表 metadata.resourceVersion 必须存在
	if rv := decode(t, body)["metadata"].(map[string]interface{})["resourceVersion"]; rv == nil || rv == "" {
		t.Fatalf("list missing resourceVersion")
	}

	// 节点
	_, body = do(t, "GET", base+"/api/v1/nodes", "")
	nodes := itemsOf(t, body)
	if len(nodes) == 0 {
		t.Fatalf("no nodes")
	}
	node := nodes[0]
	ni := node["status"].(map[string]interface{})["nodeInfo"].(map[string]interface{})
	if ni["kubeletVersion"] != "v1.28.4" || ni["containerRuntimeVersion"] != "containerd://1.7.24" {
		t.Fatalf("nodeInfo=%v", ni)
	}
	conds := node["status"].(map[string]interface{})["conditions"].([]interface{})
	if len(conds) < 4 {
		t.Fatalf("node conditions=%v", conds)
	}

	// Pod（全命名空间）
	_, body = do(t, "GET", base+"/api/v1/pods", "")
	pods := itemsOf(t, body)
	if len(pods) < 8 {
		t.Fatalf("pods=%d", len(pods))
	}
	// 命名空间过滤
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/pods", "")
	defPods := itemsOf(t, body)
	if len(defPods) == 0 {
		t.Fatalf("no default pods")
	}
	for _, p := range defPods {
		if meta(t, p)["namespace"] != "default" {
			t.Fatalf("namespace filter leaked: %v", meta(t, p)["namespace"])
		}
	}
	// Kubernetes Service（ClusterIP 10.96.0.1）
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/services/kubernetes", "")
	svc := decode(t, body)
	if svc["kind"] != "Service" || svc["spec"].(map[string]interface{})["clusterIP"] != "10.96.0.1" {
		t.Fatalf("kubernetes svc=%v", svc)
	}

	// 单个 Pod：形状完整（containerStatuses/phase/podIP）
	var podName string
	for _, p := range defPods {
		if strings.HasPrefix(meta(t, p)["name"].(string), "nginx") {
			podName = meta(t, p)["name"].(string)
		}
	}
	if podName == "" {
		t.Fatalf("nginx pod missing")
	}
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/pods/"+podName, "")
	pod := decode(t, body)
	status := pod["status"].(map[string]interface{})
	if status["phase"] != "Running" || status["podIP"] == nil {
		t.Fatalf("pod status=%v", status)
	}
	cs := status["containerStatuses"].([]interface{})
	if len(cs) != 1 {
		t.Fatalf("containerStatuses=%v", cs)
	}
	if ready := cs[0].(map[string]interface{})["ready"]; ready != true {
		t.Fatalf("container not ready")
	}
	// ownerReferences 指向 ReplicaSet
	owners := meta(t, pod)["ownerReferences"].([]interface{})
	if owners[0].(map[string]interface{})["kind"] != "ReplicaSet" {
		t.Fatalf("ownerReferences=%v", owners)
	}

	// 404 形状
	code, body := do(t, "GET", base+"/api/v1/namespaces/default/pods/nosuch", "")
	if code != 404 {
		t.Fatalf("missing pod code=%d", code)
	}
	st := decode(t, body)
	if st["kind"] != "Status" || st["status"] != "Failure" || st["reason"] != "NotFound" || st["code"].(float64) != 404 {
		t.Fatalf("status=%v", st)
	}
}

func TestSelectors(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	// labelSelector
	_, body := do(t, "GET", base+"/api/v1/namespaces/default/pods?labelSelector=app%3Dnginx", "")
	got := itemsOf(t, body)
	if len(got) != 1 || !strings.HasPrefix(meta(t, got[0])["name"].(string), "nginx-") {
		t.Fatalf("labelSelector result=%v", namesOf(t, got))
	}
	// 不存在的 label
	_, body = do(t, "GET", base+"/api/v1/pods?labelSelector=app%3Dnosuch", "")
	if n := len(itemsOf(t, body)); n != 0 {
		t.Fatalf("labelSelector expected 0 got %d", n)
	}

	// fieldSelector: spec.nodeName
	_, body = do(t, "GET", base+"/api/v1/pods?fieldSelector=spec.nodeName%3Dnode-1", "")
	if n := len(itemsOf(t, body)); n == 0 {
		t.Fatalf("fieldSelector nodeName returned 0")
	}
	_, body = do(t, "GET", base+"/api/v1/pods?fieldSelector=spec.nodeName%3Dnode-9", "")
	if n := len(itemsOf(t, body)); n != 0 {
		t.Fatalf("fieldSelector node-9 expected 0 got %d", n)
	}

	// events 按 involvedObject 过滤（kubectl describe 用）
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/events?fieldSelector=involvedObject.name%3Dnginx-7d8f9c6b5-x2k4p", "")
	if n := len(itemsOf(t, body)); n == 0 {
		t.Fatalf("events fieldSelector returned 0")
	}
}

// ---- CRUD ----

func TestCRUD(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"app-config","namespace":"default"},"data":{"mode":"prod"}}`
	code, body := do(t, "POST", base+"/api/v1/namespaces/default/configmaps", cm)
	if code != 201 {
		t.Fatalf("create code=%d body=%s", code, body)
	}
	created := decode(t, body)
	m := meta(t, created)
	if m["uid"] == nil || m["resourceVersion"] == nil || m["creationTimestamp"] == nil {
		t.Fatalf("create metadata incomplete: %v", m)
	}
	rv := m["resourceVersion"].(string)

	// 重复创建 -> 409 AlreadyExists
	if code, body := do(t, "POST", base+"/api/v1/namespaces/default/configmaps", cm); code != 409 ||
		!strings.Contains(body, "AlreadyExists") {
		t.Fatalf("duplicate create = %d %s", code, body)
	}

	// 读取
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/configmaps/app-config", "")
	if decode(t, body)["data"].(map[string]interface{})["mode"] != "prod" {
		t.Fatalf("get=%s", body)
	}

	// 更新（带正确 rv）
	upd := fmt.Sprintf(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"app-config","namespace":"default","resourceVersion":%q},"data":{"mode":"staging"}}`, rv)
	if code, body := do(t, "PUT", base+"/api/v1/namespaces/default/configmaps/app-config", upd); code != 200 {
		t.Fatalf("update code=%d body=%s", code, body)
	}
	// 旧 rv 更新 -> 409 Conflict
	stale := fmt.Sprintf(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"app-config","namespace":"default","resourceVersion":%q},"data":{"mode":"x"}}`, rv)
	if code, body := do(t, "PUT", base+"/api/v1/namespaces/default/configmaps/app-config", stale); code != 409 ||
		!strings.Contains(body, "Conflict") {
		t.Fatalf("stale update = %d %s", code, body)
	}

	// PATCH merge-patch：改一个键、删一个键
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/configmaps/app-config", "")
	if code, body := doCT(t, "PATCH", base+"/api/v1/namespaces/default/configmaps/app-config",
		"application/merge-patch+json", `{"data":{"mode":"prod","extra":"1"}}`); code != 200 {
		t.Fatalf("patch code=%d body=%s", code, body)
	}

	// 创建到不存在的命名空间 -> 404
	code, body = do(t, "POST", base+"/api/v1/namespaces/ghost/configmaps", cm)
	if code != 404 {
		t.Fatalf("create in missing ns code=%d body=%s", code, body)
	}
	if msg, _ := decode(t, body)["message"].(string); !strings.Contains(msg, `namespaces "ghost" not found`) {
		t.Fatalf("create in missing ns message=%q", msg)
	}

	// generateName
	gen := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"generateName":"generated-"}}`
	code, body = do(t, "POST", base+"/api/v1/namespaces/default/configmaps", gen)
	if code != 201 {
		t.Fatalf("generateName code=%d", code)
	}
	genName := meta(t, decode(t, body))["name"].(string)
	if !strings.HasPrefix(genName, "generated-") || len(genName) <= len("generated-") {
		t.Fatalf("generated name=%q", genName)
	}

	// 删除
	if code, _ := do(t, "DELETE", base+"/api/v1/namespaces/default/configmaps/app-config", ""); code != 200 {
		t.Fatalf("delete code=%d", code)
	}
	if code, _ := do(t, "GET", base+"/api/v1/namespaces/default/configmaps/app-config", ""); code != 404 {
		t.Fatalf("get after delete code=%d", code)
	}
}

func TestApplyYAML(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	manifest := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: applied\n  namespace: default\ndata:\n  a: b\n"
	// 不存在时 apply 会创建
	code, body := doCT(t, "PATCH", base+"/api/v1/namespaces/default/configmaps/applied",
		"application/apply-patch+yaml", manifest)
	if code != 201 {
		t.Fatalf("apply create code=%d body=%s", code, body)
	}
	if code, _ := do(t, "GET", base+"/api/v1/namespaces/default/configmaps/applied", ""); code != 200 {
		t.Fatalf("applied object not found")
	}
	// 再次 apply（已存在）-> 200
	manifest2 := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: applied\n  namespace: default\ndata:\n  a: c\n"
	if code, body := doCT(t, "PATCH", base+"/api/v1/namespaces/default/configmaps/applied",
		"application/apply-patch+yaml", manifest2); code != 200 {
		t.Fatalf("apply update code=%d body=%s", code, body)
	}
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/configmaps/applied", "")
	if decode(t, body)["data"].(map[string]interface{})["a"] != "c" {
		t.Fatalf("apply did not update: %s", body)
	}
}

func TestDeleteCollectionAndPagination(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	// 分页：limit=2 返回 2 条与 continue
	code, body := do(t, "GET", base+"/api/v1/pods?limit=2", "")
	if code != 200 {
		t.Fatalf("limit code=%d", code)
	}
	first := itemsOf(t, body)
	if len(first) != 2 {
		t.Fatalf("limit=2 returned %d", len(first))
	}
	cont, _ := decode(t, body)["metadata"].(map[string]interface{})["continue"].(string)
	if cont == "" {
		t.Fatalf("missing continue token")
	}
	_, body = do(t, "GET", base+"/api/v1/pods?limit=2&continue="+cont, "")
	second := itemsOf(t, body)
	if len(second) != 2 {
		t.Fatalf("second page=%d", len(second))
	}
	if namesOf(t, first)[0] == namesOf(t, second)[0] {
		t.Fatalf("pages overlap")
	}

	// deletecollection
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/configmaps", "")
	before := len(itemsOf(t, body))
	if before == 0 {
		t.Fatalf("no configmaps to delete")
	}
	if code, _ := do(t, "DELETE", base+"/api/v1/namespaces/default/configmaps", ""); code != 200 {
		t.Fatalf("deletecollection code=%d", code)
	}
	_, body = do(t, "GET", base+"/api/v1/namespaces/default/configmaps", "")
	if after := len(itemsOf(t, body)); after != 0 {
		t.Fatalf("configmaps after deletecollection=%d", after)
	}
}

// ---- 子资源 ----

func TestScaleSubresource(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	code, body := do(t, "GET", base+"/apis/apps/v1/namespaces/default/deployments/nginx/scale", "")
	if code != 200 {
		t.Fatalf("scale get code=%d", code)
	}
	sc := decode(t, body)
	if sc["kind"] != "Scale" || sc["spec"].(map[string]interface{})["replicas"].(float64) != 1 {
		t.Fatalf("scale=%v", sc)
	}
	// 缩到 3 副本
	if code, body := do(t, "PUT", base+"/apis/apps/v1/namespaces/default/deployments/nginx/scale",
		`{"spec":{"replicas":3}}`); code != 200 {
		t.Fatalf("scale put code=%d body=%s", code, body)
	}
	_, body = do(t, "GET", base+"/apis/apps/v1/namespaces/default/deployments/nginx", "")
	if n := decode(t, body)["spec"].(map[string]interface{})["replicas"].(float64); n != 3 {
		t.Fatalf("deployment replicas=%v want 3", n)
	}
}

func TestPodLogAndExec(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	code, body := do(t, "GET", base+"/api/v1/namespaces/default/pods/nginx-7d8f9c6b5-x2k4p/log", "")
	if code != 200 || !strings.Contains(body, "nginx/1.25.3") {
		t.Fatalf("pod log = %d %q", code, body)
	}
	if code, _ := do(t, "GET", base+"/api/v1/namespaces/default/pods/nosuch/log", ""); code != 404 {
		t.Fatalf("missing pod log code=%d", code)
	}
	// exec 需要 SPDY 升级
	code, body = do(t, "POST", base+"/api/v1/namespaces/default/pods/nginx-7d8f9c6b5-x2k4p/exec", "")
	if code != 400 || !strings.Contains(body, "Upgrade request required") {
		t.Fatalf("exec = %d %q", code, body)
	}
}

// ---- watch ----

func TestWatch(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()

	// watch 1 秒：应收到现有 Pod 的 ADDED 事件后结束
	start := time.Now()
	code, body := do(t, "GET", "https://"+addr+"/api/v1/pods?watch=1&timeoutSeconds=1", "")
	if code != 200 {
		t.Fatalf("watch code=%d", code)
	}
	if !strings.Contains(body, `"type":"ADDED"`) {
		t.Fatalf("watch body=%q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, `"kind":"Pod"`) {
		t.Fatalf("watch did not include pod objects")
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("watch returned too fast: %v", elapsed)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- 认证/授权/指标 ----

func TestAuthReviews(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	code, body := do(t, "POST", base+"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
		`{"spec":{"resourceAttributes":{"namespace":"default","verb":"get","resource":"pods"}}}`)
	if code != 201 {
		t.Fatalf("ssar code=%d body=%s", code, body)
	}
	ssar := decode(t, body)
	if ssar["kind"] != "SelfSubjectAccessReview" || ssar["status"].(map[string]interface{})["allowed"] != true {
		t.Fatalf("ssar=%v", ssar)
	}

	code, body = do(t, "POST", base+"/apis/authentication.k8s.io/v1/tokenreviews", `{"spec":{"token":"x"}}`)
	if code != 201 || decode(t, body)["status"].(map[string]interface{})["authenticated"] != true {
		t.Fatalf("tokenreview = %d %s", code, body)
	}
}

func TestMetricsAPI(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	code, body := do(t, "GET", base+"/apis/metrics.k8s.io/v1beta1/nodes", "")
	if code != 200 {
		t.Fatalf("node metrics code=%d", code)
	}
	nm := decode(t, body)
	if nm["kind"] != "NodeMetricsList" || len(nm["items"].([]interface{})) == 0 {
		t.Fatalf("node metrics=%v", nm)
	}
	if usage := nm["items"].([]interface{})[0].(map[string]interface{})["usage"].(map[string]interface{}); usage["cpu"] != "482m" {
		t.Fatalf("node usage=%v", usage)
	}
	code, body = do(t, "GET", base+"/apis/metrics.k8s.io/v1beta1/namespaces/default/pods", "")
	if code != 200 || !strings.Contains(body, "PodMetricsList") {
		t.Fatalf("pod metrics = %d", code)
	}
}

// TestTableOutput kubectl 默认请求 Table（Accept as=Table），必须返回标准列。
func TestTableOutput(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "https://" + addr

	req, err := http.NewRequest("GET", base+"/api/v1/namespaces/default/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io,application/json")
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	table := decode(t, string(body))
	if table["kind"] != "Table" || table["apiVersion"] != "meta.k8s.io/v1" {
		t.Fatalf("table kind=%v apiVersion=%v", table["kind"], table["apiVersion"])
	}
	cols, _ := table["columnDefinitions"].([]interface{})
	names := make([]string, 0, len(cols))
	for _, c := range cols {
		names = append(names, c.(map[string]interface{})["name"].(string))
	}
	// 标准列 + wide 列（priority>0）
	want := []string{"Name", "Ready", "Status", "Restarts", "Age", "IP", "Node", "Nominated Node", "Readiness Gates"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("pod table columns=%v", names)
	}
	// wide 列必须带 priority
	last := cols[len(cols)-1].(map[string]interface{})
	if last["priority"].(float64) != 1 {
		t.Fatalf("wide column priority=%v", last["priority"])
	}
	rows, _ := table["rows"].([]interface{})
	if len(rows) != 3 {
		t.Fatalf("pod table rows=%d", len(rows))
	}
	cells := rows[0].(map[string]interface{})["cells"].([]interface{})
	if len(cells) != len(cols) {
		t.Fatalf("cells=%d columns=%d", len(cells), len(cols))
	}
	// 第一行按名字排序是 broken-app（CrashLoopBackOff，0/1，6 次重启）
	if cells[1] != "0/1" || cells[2] != "CrashLoopBackOff" || cells[3] != "6" {
		t.Fatalf("broken-app cells=%v", cells)
	}
	// 行里带 PartialObjectMetadata
	obj := rows[0].(map[string]interface{})["object"].(map[string]interface{})
	if obj["kind"] != "PartialObjectMetadata" || obj["apiVersion"] != "meta.k8s.io/v1" {
		t.Fatalf("row object=%v", obj)
	}

	// nodes 表：STATUS/ROLES/VERSION
	req, _ = http.NewRequest("GET", base+"/api/v1/nodes", nil)
	req.Header.Set("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io,application/json")
	resp2, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	b2, _ := io.ReadAll(resp2.Body)
	nt := decode(t, string(b2))
	nodeCells := nt["rows"].([]interface{})[0].(map[string]interface{})["cells"].([]interface{})
	if nodeCells[1] != "Ready" || nodeCells[2] != "control-plane" || nodeCells[4] != "v1.28.4" {
		t.Fatalf("node cells=%v", nodeCells)
	}

	// 单对象 Table（kubectl get pod xxx）
	req, _ = http.NewRequest("GET", base+"/api/v1/namespaces/default/pods/nginx-7d8f9c6b5-x2k4p", nil)
	req.Header.Set("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io,application/json")
	resp3, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	b3, _ := io.ReadAll(resp3.Body)
	st := decode(t, string(b3))
	if st["kind"] != "Table" || len(st["rows"].([]interface{})) != 1 {
		t.Fatalf("single object table=%v", st["kind"])
	}
}

// ---- 配置 ----

func TestConfigOverrides(t *testing.T) {
	cfg := kubernetesConfig{
		store:        newK8sStore(),
		Version:      "v1.29.3",
		GitCommit:    "deadbeefcafe",
		GoVersion:    "go1.21.8",
		BuildDate:    "2024-02-14T00:00:00Z",
		Platform:     "linux/arm64",
		IdleTimeoutS: 42,
		Namespaces:   []string{"monitoring", "ingress-nginx"},
		Nodes: []k8sNodeConfig{
			{Name: "cp-1", CPU: "8", Memory: "16Gi", ControlPlane: true},
			{Name: "worker-1", CPU: "16", Memory: "32Gi"},
		},
		Pods: []k8sPodConfig{
			{Name: "app-1", Namespace: "monitoring", Image: "prom/prometheus:v2.48.0"},
		},
	}
	if got := cfg.idleTimeout(); got != 42*time.Second {
		t.Fatalf("idleTimeout=%v", got)
	}
	addr, stop := startTestServer(t, cfg)
	defer stop()
	base := "https://" + addr

	// /version 跟随配置
	_, body := do(t, "GET", base+"/version", "")
	v := decode(t, body)
	if v["major"] != "1" || v["minor"] != "29" || v["gitVersion"] != "v1.29.3" ||
		v["gitCommit"] != "deadbeefcafe" || v["goVersion"] != "go1.21.8" ||
		v["buildDate"] != "2024-02-14T00:00:00Z" || v["platform"] != "linux/arm64" {
		t.Fatalf("version=%v", v)
	}

	// 追加命名空间 + 默认四个仍在
	_, body = do(t, "GET", base+"/api/v1/namespaces", "")
	nss := namesOf(t, itemsOf(t, body))
	for _, want := range []string{"default", "kube-system", "monitoring", "ingress-nginx"} {
		if !containsStr(nss, want) {
			t.Fatalf("namespaces=%v missing %q", nss, want)
		}
	}

	// 自定义节点
	_, body = do(t, "GET", base+"/api/v1/nodes", "")
	nodes := itemsOf(t, body)
	if len(nodes) != 2 {
		t.Fatalf("nodes=%d want 2", len(nodes))
	}
	foundWorker := false
	for _, n := range nodes {
		if meta(t, n)["name"] == "worker-1" {
			foundWorker = true
			cap := n["status"].(map[string]interface{})["capacity"].(map[string]interface{})
			if cap["cpu"] != "16" || cap["memory"] != "32Gi" {
				t.Fatalf("worker capacity=%v", cap)
			}
		}
	}
	if !foundWorker {
		t.Fatalf("worker-1 missing")
	}

	// 自定义 Pod
	_, body = do(t, "GET", base+"/api/v1/namespaces/monitoring/pods", "")
	pods := itemsOf(t, body)
	if len(pods) != 1 || meta(t, pods[0])["name"] != "app-1" {
		t.Fatalf("configured pods=%v", namesOf(t, pods))
	}
}
