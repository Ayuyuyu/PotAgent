package kubernetes

/*
Kubernetes 蜜罐服务（TCP 6443，Kubernetes API Server，JSON over HTTPS）。

保真度策略（对齐 services/docker 的实现水位）：
  - 自签证书 HTTPS（可配 cert_file/key_file），keep-alive 循环，空闲超时关闭。
  - Discovery 完整三层：/api、/api/v1、/apis、/apis/{group}、/apis/{group}/{version}，
    资源清单（APIResourceList）按真实 kube-apiserver 的 verbs/shortNames/categories 下发。
  - 资源路由泛化：/api/v1/{resource}、/api/v1/namespaces/{ns}/{resource}[/{name}[/{sub}]]，
    以及 /apis/{group}/{version}/... 同样形态；支持 GET/POST/PUT/PATCH/DELETE。
  - 支持 labelSelector / fieldSelector / limit / continue / watch（chunked 事件流）。
  - 子资源：pods/log（纯文本日志）、pods/status、deployments/scale、services/proxy；
    exec/attach/portforward 按真机返回 400 "Upgrade request required"（不实现 SPDY）。
  - 对象形状按真机：nodes（capacity/allocatable/conditions/nodeInfo/addresses）、
    pods（containerStatuses/conditions/qosClass/podIP/ownerReferences）、deployments
    （replicas/readyReplicas/availableReplicas/conditions）、services（clusterIP/ports）、
    events（involvedObject），describe/get -o yaml/wide 都有内容可看。
  - 错误统一为 K8s Status（reason: NotFound/AlreadyExists/Conflict/BadRequest/
    MethodNotAllowed/Forbidden），响应头带 Audit-Id / Cache-Control，与真机一致。
  - 预置诱饵：命名空间、节点、Pod/Deployment/ReplicaSet/Service/Endpoints/ConfigMap/
    Secret/ServiceAccount/Event/PV/PVC/Ingress/DaemonSet/StorageClass/RBAC 角色。
  - 版本指纹与主机信息可配（version/git_commit/build_date/go_version/platform/
    node 配置/namespace 配置）；每类资源的种子也可在 yaml 覆盖。
  - 无认证：不校验 Bearer Token（模拟暴露在公网的未授权 API Server），
    Authorization 头与解析出的 token 原样落事件；authz 自查询一律 allowed。
  - 事件 k8s-connect / k8s-request / k8s-close；k8s-request 含 method/url/path/query/
    host/user-agent/content-length/body/authorization/token，均带 k8s.session-id(xid)。
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
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
	"gopkg.in/yaml.v3"
)

const (
	defaultVersion   = "v1.28.4"
	defaultGitCommit = "b7a3e7d1d4a3e8f9c0d1e2f3a4b5c6d7e8f9a0b"
	defaultGoVersion = "go1.20.7"
	defaultBuildDate = "2023-11-14T10:22:29Z"
	defaultPlatform  = "linux/amd64"

	defaultNodeCPU    = "4"
	defaultNodeMemory = "8123456Ki"

	maxBody = 1 << 20
)

// defaultIdleTimeout 单连接空闲超时（yaml idle_timeout_sec 可覆盖）。
const defaultIdleTimeout = 300 * time.Second

var (
	serviceName = "kubernetes"
	_           = services.Register(serviceName, KubernetesServiceInit)
)

func KubernetesServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   k8sHandle,
		ServiceOptions: kubernetesConfig{store: newK8sStore()},
	}
}

// kubernetesConfig 协议专属配置。留空均回退内置默认值。
type kubernetesConfig struct {
	store *k8sStore
	// 版本指纹
	Version   string `mapstructure:"version"`
	GitCommit string `mapstructure:"git_commit"`
	GoVersion string `mapstructure:"go_version"`
	BuildDate string `mapstructure:"build_date"`
	Platform  string `mapstructure:"platform"`
	// TLS
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	// 行为
	IdleTimeoutS int `mapstructure:"idle_timeout_sec"`
	// 种子数据
	Namespaces []string        `mapstructure:"namespaces"`
	Nodes      []k8sNodeConfig `mapstructure:"nodes"`
	Pods       []k8sPodConfig  `mapstructure:"pods"`
}

// k8sNodeConfig 预置节点（cpu/memory 直接按 K8s quantity 写，如 "4"/"8Gi"）。
type k8sNodeConfig struct {
	Name         string `mapstructure:"name"`
	CPU          string `mapstructure:"cpu"`
	Memory       string `mapstructure:"memory"`
	ControlPlane bool   `mapstructure:"control_plane"`
}

// k8sPodConfig 预置 Pod（image/phase 留空取默认）。
type k8sPodConfig struct {
	Name      string `mapstructure:"name"`
	Namespace string `mapstructure:"namespace"`
	Image     string `mapstructure:"image"`
	Phase     string `mapstructure:"phase"`
}

func strOr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (c kubernetesConfig) version() string   { return strOr(c.Version, defaultVersion) }
func (c kubernetesConfig) gitCommit() string { return strOr(c.GitCommit, defaultGitCommit) }
func (c kubernetesConfig) goVersion() string { return strOr(c.GoVersion, defaultGoVersion) }
func (c kubernetesConfig) buildDate() string { return strOr(c.BuildDate, defaultBuildDate) }
func (c kubernetesConfig) platform() string  { return strOr(c.Platform, defaultPlatform) }

func (c kubernetesConfig) idleTimeout() time.Duration {
	if c.IdleTimeoutS > 0 {
		return time.Duration(c.IdleTimeoutS) * time.Second
	}
	return defaultIdleTimeout
}

// ---- 资源清单（discovery 与路由共用）----

type resourceDef struct {
	group      string // "" 表示 core
	version    string
	name       string // 复数
	singular   string
	kind       string
	namespaced bool
	shortNames []string
	categories []string
}

func (d resourceDef) apiVersion() string {
	if d.group == "" {
		return d.version
	}
	return d.group + "/" + d.version
}

var defaultVerbs = []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}

// resourceDefs 覆盖攻击者/运维最常用的一批资源；未知资源按 404 处理。
var resourceDefs = []resourceDef{
	// core/v1
	{"", "v1", "pods", "pod", "Pod", true, []string{"po"}, []string{"all"}},
	{"", "v1", "services", "service", "Service", true, []string{"svc"}, []string{"all"}},
	{"", "v1", "namespaces", "namespace", "Namespace", false, []string{"ns"}, nil},
	{"", "v1", "nodes", "node", "Node", false, []string{"no"}, nil},
	{"", "v1", "configmaps", "configmap", "ConfigMap", true, []string{"cm"}, nil},
	{"", "v1", "secrets", "secret", "Secret", true, nil, nil},
	{"", "v1", "serviceaccounts", "serviceaccount", "ServiceAccount", true, []string{"sa"}, nil},
	{"", "v1", "endpoints", "endpoints", "Endpoints", true, []string{"ep"}, nil},
	{"", "v1", "events", "event", "Event", true, []string{"ev"}, nil},
	{"", "v1", "persistentvolumes", "persistentvolume", "PersistentVolume", false, []string{"pv"}, nil},
	{"", "v1", "persistentvolumeclaims", "persistentvolumeclaim", "PersistentVolumeClaim", true, []string{"pvc"}, nil},
	{"", "v1", "resourcequotas", "resourcequota", "ResourceQuota", true, []string{"quota"}, nil},
	{"", "v1", "limitranges", "limitrange", "LimitRange", true, []string{"limits"}, nil},
	// apps/v1
	{"apps", "v1", "deployments", "deployment", "Deployment", true, []string{"deploy"}, []string{"all"}},
	{"apps", "v1", "replicasets", "replicaset", "ReplicaSet", true, []string{"rs"}, []string{"all"}},
	{"apps", "v1", "statefulsets", "statefulset", "StatefulSet", true, []string{"sts"}, []string{"all"}},
	{"apps", "v1", "daemonsets", "daemonset", "DaemonSet", true, []string{"ds"}, []string{"all"}},
	// batch/v1
	{"batch", "v1", "jobs", "job", "Job", true, nil, []string{"all"}},
	{"batch", "v1", "cronjobs", "cronjob", "CronJob", true, []string{"cj"}, []string{"all"}},
	// networking.k8s.io/v1
	{"networking.k8s.io", "v1", "ingresses", "ingress", "Ingress", true, []string{"ing"}, nil},
	{"networking.k8s.io", "v1", "networkpolicies", "networkpolicy", "NetworkPolicy", true, []string{"netpol"}, nil},
	// rbac.authorization.k8s.io/v1
	{"rbac.authorization.k8s.io", "v1", "roles", "role", "Role", true, nil, nil},
	{"rbac.authorization.k8s.io", "v1", "rolebindings", "rolebinding", "RoleBinding", true, nil, nil},
	{"rbac.authorization.k8s.io", "v1", "clusterroles", "clusterrole", "ClusterRole", false, nil, nil},
	{"rbac.authorization.k8s.io", "v1", "clusterrolebindings", "clusterrolebinding", "ClusterRoleBinding", false, nil, nil},
	// storage.k8s.io/v1
	{"storage.k8s.io", "v1", "storageclasses", "storageclass", "StorageClass", false, []string{"sc"}, nil},
	// policy/v1
	{"policy", "v1", "poddisruptionbudgets", "poddisruptionbudget", "PodDisruptionBudget", true, []string{"pdb"}, nil},
	// autoscaling/v2
	{"autoscaling", "v2", "horizontalpodautoscalers", "horizontalpodautoscaler", "HorizontalPodAutoscaler", true, []string{"hpa"}, nil},
	// coordination.k8s.io/v1
	{"coordination.k8s.io", "v1", "leases", "lease", "Lease", true, nil, nil},
	// apiextensions.k8s.io/v1
	{"apiextensions.k8s.io", "v1", "customresourcedefinitions", "customresourcedefinition", "CustomResourceDefinition", false, []string{"crd", "crds"}, nil},
	// authorization/authentication 自查询（POST 专用，不落库）
	{"authorization.k8s.io", "v1", "selfsubjectaccessreviews", "selfsubjectaccessreview", "SelfSubjectAccessReview", false, nil, nil},
	{"authorization.k8s.io", "v1", "selfsubjectrulesreviews", "selfsubjectrulesreview", "SelfSubjectRulesReview", false, nil, nil},
	{"authorization.k8s.io", "v1", "subjectaccessreviews", "subjectaccessreview", "SubjectAccessReview", false, nil, nil},
	{"authorization.k8s.io", "v1", "localsubjectaccessreviews", "localsubjectaccessreview", "LocalSubjectAccessReview", true, nil, nil},
	{"authentication.k8s.io", "v1", "tokenreviews", "tokenreview", "TokenReview", false, nil, nil},
	// metrics.k8s.io/v1beta1（只读指标，kubectl top）
	{"metrics.k8s.io", "v1beta1", "nodes", "node", "NodeMetrics", false, nil, nil},
	{"metrics.k8s.io", "v1beta1", "pods", "pod", "PodMetrics", true, nil, nil},
}

// apiGroups discovery 里的组顺序（真机按字母序）。
var apiGroups = []struct {
	name     string
	versions []string
}{
	{"apiextensions.k8s.io", []string{"v1"}},
	{"apps", []string{"v1"}},
	{"authentication.k8s.io", []string{"v1"}},
	{"authorization.k8s.io", []string{"v1"}},
	{"autoscaling", []string{"v1", "v2"}},
	{"batch", []string{"v1"}},
	{"coordination.k8s.io", []string{"v1"}},
	{"metrics.k8s.io", []string{"v1beta1"}},
	{"networking.k8s.io", []string{"v1"}},
	{"policy", []string{"v1"}},
	{"rbac.authorization.k8s.io", []string{"v1"}},
	{"storage.k8s.io", []string{"v1"}},
}

func findResourceDef(group, version, name string) (resourceDef, bool) {
	for _, d := range resourceDefs {
		if d.group == group && d.version == version && d.name == name {
			return d, true
		}
	}
	// 允许用单数名或 kind 小写访问（真机也支持部分别名）
	for _, d := range resourceDefs {
		if d.group == group && d.version == version && (d.singular == name || strings.ToLower(d.kind) == name) {
			return d, true
		}
	}
	return resourceDef{}, false
}

func defsFor(group, version string) []resourceDef {
	out := make([]resourceDef, 0)
	for _, d := range resourceDefs {
		if d.group == group && d.version == version {
			out = append(out, d)
		}
	}
	return out
}

// ---- 数据存储 ----

// k8sStore 内存态对象库：key = group|resource|namespace|name。
type k8sStore struct {
	mu      sync.Mutex
	seeded  bool
	rv      int64
	objects map[string]map[string]interface{}
}

func newK8sStore() *k8sStore {
	return &k8sStore{objects: map[string]map[string]interface{}{}}
}

func objKey(group, resource, namespace, name string) string {
	return group + "|" + resource + "|" + namespace + "|" + name
}

// nextRVLocked 单调递增的 resourceVersion。调用方需持有锁。
func (s *k8sStore) nextRVLocked() string {
	s.rv++
	return strconv.FormatInt(s.rv, 10)
}

func (s *k8sStore) putLocked(group, resource, ns, name string, obj map[string]interface{}) {
	meta, _ := obj["metadata"].(map[string]interface{})
	if meta == nil {
		meta = map[string]interface{}{}
		obj["metadata"] = meta
	}
	if v, ok := meta["uid"].(string); !ok || v == "" {
		meta["uid"] = newUUID()
	}
	// 客户端常在创建请求里带 "creationTimestamp": null，这里统一补真实时间
	if v, ok := meta["creationTimestamp"].(string); !ok || v == "" {
		meta["creationTimestamp"] = nowTS()
	}
	meta["resourceVersion"] = s.nextRVLocked()
	if ns != "" {
		meta["namespace"] = ns
	}
	if name != "" {
		meta["name"] = name
	}
	s.objects[objKey(group, resource, ns, name)] = obj
}

func (s *k8sStore) getLocked(group, resource, ns, name string) (map[string]interface{}, bool) {
	obj, ok := s.objects[objKey(group, resource, ns, name)]
	return obj, ok
}

func (s *k8sStore) listLocked(group, resource, ns string, allNamespaces bool) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for k, obj := range s.objects {
		parts := strings.SplitN(k, "|", 4)
		if len(parts) != 4 || parts[0] != group || parts[1] != resource {
			continue
		}
		if !allNamespaces && parts[2] != ns {
			continue
		}
		out = append(out, obj)
	}
	sort.Slice(out, func(i, j int) bool {
		mi, _ := out[i]["metadata"].(map[string]interface{})
		mj, _ := out[j]["metadata"].(map[string]interface{})
		ni, _ := mi["namespace"].(string)
		nj, _ := mj["namespace"].(string)
		if ni != nj {
			return ni < nj
		}
		ai, _ := mi["name"].(string)
		aj, _ := mj["name"].(string)
		return ai < aj
	})
	return out
}

// ---- 种子数据 ----

func (s *k8sStore) ensureSeeded(cfg kubernetesConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seeded {
		return
	}
	s.seeded = true

	// 命名空间：四个内置 + 配置追加
	namespaces := []string{"default", "kube-system", "kube-public", "kube-node-lease"}
	for _, ns := range cfg.Namespaces {
		ns = strings.TrimSpace(ns)
		if ns == "" || containsStr(namespaces, ns) {
			continue
		}
		namespaces = append(namespaces, ns)
	}
	for _, ns := range namespaces {
		s.putLocked("", "namespaces", "", ns, map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]interface{}{
				"name":              ns,
				"labels":            map[string]interface{}{"kubernetes.io/metadata.name": ns},
				"creationTimestamp": tsAgo(30 * 24 * time.Hour),
			},
			"spec":   map[string]interface{}{"finalizers": []interface{}{"kubernetes"}},
			"status": map[string]interface{}{"phase": "Active"},
		})
	}

	// 节点
	nodes := cfg.Nodes
	if len(nodes) == 0 {
		nodes = []k8sNodeConfig{{Name: "node-1", CPU: defaultNodeCPU, Memory: defaultNodeMemory, ControlPlane: true}}
	}
	for i, nc := range nodes {
		name := strOr(nc.Name, fmt.Sprintf("node-%d", i+1))
		s.putLocked("", "nodes", "", name, nodeObject(cfg, name, nc))
	}

	// 工作负载：Deployment/ReplicaSet/Pod 三层联动，名字与 ownerReferences 自洽
	s.putLocked("apps", "deployments", "default", "nginx", deploymentObject("nginx", "default", "nginx", "nginx:1.25.3", 1, 1, "7d8f9c6b5"))
	s.putLocked("apps", "deployments", "default", "redis", deploymentObject("redis", "default", "redis", "redis:7.2.3", 1, 1, "5f6b7c8d9"))
	s.putLocked("apps", "deployments", "kube-system", "coredns", deploymentObject("coredns", "kube-system", "k8s-app", "registry.k8s.io/coredns/coredns:v1.10.1", 2, 2, "5dd5756b68"))
	s.putLocked("apps", "replicasets", "default", "nginx-7d8f9c6b5", replicaSetObject("nginx-7d8f9c6b5", "default", "nginx", "nginx:1.25.3", 1, "7d8f9c6b5"))
	s.putLocked("apps", "replicasets", "default", "redis-5f6b7c8d9", replicaSetObject("redis-5f6b7c8d9", "default", "redis", "redis:7.2.3", 1, "5f6b7c8d9"))
	s.putLocked("apps", "replicasets", "kube-system", "coredns-5dd5756b68", replicaSetObject("coredns-5dd5756b68", "kube-system", "k8s-app", "registry.k8s.io/coredns/coredns:v1.10.1", 2, "5dd5756b68"))

	// Pod：配置优先；留空用内置诱饵（含 owner 关系与 containerStatuses）
	pods := cfg.Pods
	if len(pods) == 0 {
		pods = []k8sPodConfig{
			{Name: "nginx-7d8f9c6b5-x2k4p", Namespace: "default", Image: "nginx:1.25.3"},
			{Name: "redis-5f6b7c8d9-q8m3n", Namespace: "default", Image: "redis:7.2.3"},
			{Name: "coredns-5dd5756b68-x9v2t", Namespace: "kube-system", Image: "registry.k8s.io/coredns/coredns:v1.10.1"},
			{Name: "coredns-5dd5756b68-t7p4s", Namespace: "kube-system", Image: "registry.k8s.io/coredns/coredns:v1.10.1"},
			{Name: "etcd-node-1", Namespace: "kube-system", Image: "registry.k8s.io/etcd:3.5.9-0"},
			{Name: "kube-apiserver-node-1", Namespace: "kube-system", Image: "registry.k8s.io/kube-apiserver:v1.28.4"},
			{Name: "kube-controller-manager-node-1", Namespace: "kube-system", Image: "registry.k8s.io/kube-controller-manager:v1.28.4"},
			{Name: "kube-scheduler-node-1", Namespace: "kube-system", Image: "registry.k8s.io/kube-scheduler:v1.28.4"},
			{Name: "kube-proxy-qm5vz", Namespace: "kube-system", Image: "registry.k8s.io/kube-proxy:v1.28.4"},
			{Name: "broken-app-6b7d9f8c5-w4x7z", Namespace: "default", Image: "ghcr.io/acme/broken-app:0.3.1", Phase: "Running"},
		}
	}
	for i, pc := range pods {
		name := strOr(pc.Name, fmt.Sprintf("pod-%d", i+1))
		ns := strOr(pc.Namespace, "default")
		image := strOr(pc.Image, "nginx:latest")
		owner := ownerRefForPod(ns, name)
		restarts := 0
		phase := strOr(pc.Phase, "Running")
		if strings.HasPrefix(name, "broken-app") {
			restarts = 6
		}
		s.putLocked("", "pods", ns, name, podObject(name, ns, image, phase, restarts, owner, i))
	}

	// Service / Endpoints
	s.putLocked("", "services", "default", "kubernetes", serviceObject("kubernetes", "default", "10.96.0.1", 443, "https", "TCP", 6443, map[string]interface{}{"component": "apiserver", "provider": "kubernetes"}))
	s.putLocked("", "services", "default", "nginx", serviceObject("nginx", "default", "10.96.123.45", 80, "http", "TCP", 80, map[string]interface{}{"app": "nginx"}))
	s.putLocked("", "services", "kube-system", "kube-dns", serviceObject("kube-dns", "kube-system", "10.96.0.10", 53, "dns", "UDP", 53, map[string]interface{}{"k8s-app": "kube-dns"}))
	s.putLocked("", "endpoints", "default", "kubernetes", endpointsObject("kubernetes", "default", "192.168.1.10", "https", 6443, "TCP"))
	s.putLocked("", "endpoints", "default", "nginx", endpointsObject("nginx", "default", "10.244.0.5", "http", 80, "TCP"))
	s.putLocked("", "endpoints", "kube-system", "kube-dns", endpointsObject("kube-dns", "kube-system", "10.244.0.7", "dns", 53, "UDP"))

	// ConfigMap
	s.putLocked("", "configmaps", "kube-system", "coredns", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name": "coredns", "namespace": "kube-system",
			"labels": map[string]interface{}{"k8s-app": "kube-dns"},
		},
		"data": map[string]interface{}{
			"Corefile": ".:53 {\n    errors\n    health {\n       lameduck 5s\n    }\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n       pods insecure\n       fallthrough in-addr.arpa ip6.arpa\n       ttl 30\n    }\n    prometheus :9153\n    forward . /etc/resolv.conf\n    cache 30\n    loop\n    reload\n    loadbalance\n}\n",
		},
	})
	for _, ns := range namespaces {
		s.putLocked("", "configmaps", ns, "kube-root-ca.crt", map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name": "kube-root-ca.crt", "namespace": ns,
				"annotations": map[string]interface{}{"kubernetes.io/description": "Contains a CA bundle that can be used to verify the kube-apiserver when using internal endpoints such as the internal service IP or kubernetes.default.svc. No other usage is guaranteed across distributions of Kubernetes clusters."},
			},
			"data": map[string]interface{}{"ca.crt": fakeCACert()},
		})
	}

	// Secret：放一份吸引人的镜像仓库凭证（攻击者常翻这里）
	s.putLocked("", "secrets", "default", "registry-credentials", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name": "registry-credentials", "namespace": "default",
			"annotations": map[string]interface{}{"kubectl.kubernetes.io/last-applied-configuration": "{}"},
		},
		"type": "kubernetes.io/dockerconfigjson",
		"data": map[string]interface{}{
			".dockerconfigjson": base64.StdEncoding.EncodeToString([]byte(`{"auths":{"registry.internal:5000":{"username":"deployer","password":"Gh7#pL2!qm","auth":"ZGVwbG95ZXI6R2g3I3BMMiFxbQ=="}}}`)),
		},
	})
	s.putLocked("", "secrets", "kube-system", "bootstrap-token-abcdef", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name": "bootstrap-token-abcdef", "namespace": "kube-system",
		},
		"type": "bootstrap.kubernetes.io/token",
		"data": map[string]interface{}{
			"token-id":                       base64.StdEncoding.EncodeToString([]byte("abcdef")),
			"token-secret":                   base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
			"usage-bootstrap-authentication": base64.StdEncoding.EncodeToString([]byte("true")),
			"auth-extra-groups":              base64.StdEncoding.EncodeToString([]byte("system:bootstrappers:kubeadm:default-node-token")),
		},
	})

	// ServiceAccount（1.24+ 不再自动生成 token secret）
	for _, ns := range namespaces {
		s.putLocked("", "serviceaccounts", ns, "default", map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ServiceAccount",
			"metadata":   map[string]interface{}{"name": "default", "namespace": ns},
			"secrets":    []interface{}{},
		})
	}
	s.putLocked("", "serviceaccounts", "kube-system", "coredns", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]interface{}{"name": "coredns", "namespace": "kube-system", "labels": map[string]interface{}{"k8s-app": "kube-dns"}},
	})

	// Events：kubectl describe 会按 involvedObject 拉取
	s.putLocked("", "events", "default", "nginx-7d8f9c6b5-x2k4p.17a1b2c3d4e5f6", eventObject("Pod", "nginx-7d8f9c6b5-x2k4p", "default", "Scheduled", "Successfully assigned default/nginx-7d8f9c6b5-x2k4p to node-1", "default-scheduler", "Normal"))
	s.putLocked("", "events", "default", "nginx-7d8f9c6b5-x2k4p.17a1b2c3d4e5f7", eventObject("Pod", "nginx-7d8f9c6b5-x2k4p", "default", "Pulled", "Container image \"nginx:1.25.3\" already present on machine", "kubelet", "Normal"))
	s.putLocked("", "events", "default", "nginx-7d8f9c6b5-x2k4p.17a1b2c3d4e5f8", eventObject("Pod", "nginx-7d8f9c6b5-x2k4p", "default", "Created", "Created container nginx", "kubelet", "Normal"))
	s.putLocked("", "events", "default", "nginx-7d8f9c6b5-x2k4p.17a1b2c3d4e5f9", eventObject("Pod", "nginx-7d8f9c6b5-x2k4p", "default", "Started", "Started container nginx", "kubelet", "Normal"))
	s.putLocked("", "events", "default", "broken-app-6b7d9f8c5-w4x7z.17a1b2c3d4e5fa", eventObject("Pod", "broken-app-6b7d9f8c5-w4x7z", "default", "BackOff", "Back-off restarting failed container broken-app in pod broken-app-6b7d9f8c5-w4x7z_default", "kubelet", "Warning"))

	// 节点心跳 Lease（kubectl describe node 会读它）
	s.putLocked("coordination.k8s.io", "leases", "kube-node-lease", "node-1", map[string]interface{}{
		"apiVersion": "coordination.k8s.io/v1",
		"kind":       "Lease",
		"metadata": map[string]interface{}{
			"name": "node-1", "namespace": "kube-node-lease",
			"creationTimestamp": tsAgo(30 * 24 * time.Hour),
		},
		"spec": map[string]interface{}{
			"holderIdentity":       "node-1",
			"leaseDurationSeconds": 40,
			"renewTime":            time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
			"leaseTransitions":     0,
		},
	})

	// PV/PVC/StorageClass
	s.putLocked("", "persistentvolumes", "", "pv-data", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "PersistentVolume",
		"metadata": map[string]interface{}{
			"name":       "pv-data",
			"finalizers": []interface{}{"kubernetes.io/pv-protection"},
		},
		"spec": map[string]interface{}{
			"accessModes":                   []interface{}{"ReadWriteOnce"},
			"capacity":                      map[string]interface{}{"storage": "10Gi"},
			"persistentVolumeReclaimPolicy": "Retain",
			"storageClassName":              "standard",
			"volumeMode":                    "Filesystem",
			"hostPath":                      map[string]interface{}{"path": "/data/pv-data", "type": ""},
			"claimRef": map[string]interface{}{
				"apiVersion": "v1", "kind": "PersistentVolumeClaim", "name": "data-pvc", "namespace": "default",
			},
		},
		"status": map[string]interface{}{"phase": "Bound"},
	})
	s.putLocked("", "persistentvolumeclaims", "default", "data-pvc", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   map[string]interface{}{"name": "data-pvc", "namespace": "default"},
		"spec": map[string]interface{}{
			"accessModes":      []interface{}{"ReadWriteOnce"},
			"resources":        map[string]interface{}{"requests": map[string]interface{}{"storage": "10Gi"}},
			"storageClassName": "standard",
			"volumeMode":       "Filesystem",
			"volumeName":       "pv-data",
		},
		"status": map[string]interface{}{
			"accessModes": []interface{}{"ReadWriteOnce"},
			"capacity":    map[string]interface{}{"storage": "10Gi"},
			"phase":       "Bound",
		},
	})
	s.putLocked("storage.k8s.io", "storageclasses", "", "standard", map[string]interface{}{
		"apiVersion": "storage.k8s.io/v1",
		"kind":       "StorageClass",
		"metadata": map[string]interface{}{
			"name":        "standard",
			"annotations": map[string]interface{}{"storageclass.kubernetes.io/is-default-class": "true"},
		},
		"provisioner":          "rancher.io/local-path",
		"reclaimPolicy":        "Delete",
		"volumeBindingMode":    "WaitForFirstConsumer",
		"allowVolumeExpansion": true,
	})

	// DaemonSet / Ingress / RBAC
	s.putLocked("apps", "daemonsets", "kube-system", "kube-proxy", daemonSetObject())
	s.putLocked("networking.k8s.io", "ingresses", "default", "nginx", ingressObject())
	s.putLocked("rbac.authorization.k8s.io", "clusterroles", "", "cluster-admin", map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]interface{}{
			"name":              "cluster-admin",
			"labels":            map[string]interface{}{"kubernetes.io/bootstrapping": "rbac-defaults"},
			"annotations":       map[string]interface{}{"rbac.authorization.kubernetes.io/autoupdate": "true"},
			"creationTimestamp": tsAgo(30 * 24 * time.Hour),
		},
		"rules": []interface{}{
			map[string]interface{}{"apiGroups": []interface{}{"*"}, "resources": []interface{}{"*"}, "verbs": []interface{}{"*"}},
			map[string]interface{}{"apiGroups": []interface{}{"*"}, "resources": []interface{}{"*/status"}, "verbs": []interface{}{"*"}},
		},
	})
	s.putLocked("rbac.authorization.k8s.io", "clusterrolebindings", "", "cluster-admin", map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": "cluster-admin", "labels": map[string]interface{}{"kubernetes.io/bootstrapping": "rbac-defaults"}},
		"roleRef":    map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
		"subjects":   []interface{}{map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:masters"}},
	})
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- 种子对象构造 ----

func nowTS() string { return time.Now().Format(time.RFC3339) }

func tsAgo(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }

func nodeObject(cfg kubernetesConfig, name string, nc k8sNodeConfig) map[string]interface{} {
	cpu := strOr(nc.CPU, defaultNodeCPU)
	mem := strOr(nc.Memory, defaultNodeMemory)
	labels := map[string]interface{}{
		"beta.kubernetes.io/arch": "amd64", "beta.kubernetes.io/os": "linux",
		"kubernetes.io/arch": "amd64", "kubernetes.io/hostname": name, "kubernetes.io/os": "linux",
	}
	if nc.ControlPlane {
		labels["node-role.kubernetes.io/control-plane"] = ""
	}
	now := nowTS()
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]interface{}{
			"name":              name,
			"labels":            labels,
			"annotations":       map[string]interface{}{"node.alpha.kubernetes.io/ttl": "0", "volumes.kubernetes.io/controller-managed-attach-detach": "true"},
			"creationTimestamp": tsAgo(30 * 24 * time.Hour),
		},
		"spec": map[string]interface{}{
			"podCIDR":  "10.244.0.0/24",
			"podCIDRs": []interface{}{"10.244.0.0/24"},
		},
		"status": map[string]interface{}{
			"capacity":    map[string]interface{}{"cpu": cpu, "ephemeral-storage": "102G", "hugepages-1Gi": "0", "hugepages-2Mi": "0", "memory": mem, "pods": "110"},
			"allocatable": map[string]interface{}{"cpu": cpu, "ephemeral-storage": "102G", "hugepages-1Gi": "0", "hugepages-2Mi": "0", "memory": mem, "pods": "110"},
			"conditions": []interface{}{
				map[string]interface{}{"type": "MemoryPressure", "status": "False", "reason": "KubeletHasSufficientMemory", "message": "kubelet has sufficient memory available", "lastHeartbeatTime": now, "lastTransitionTime": tsAgo(30 * 24 * time.Hour)},
				map[string]interface{}{"type": "DiskPressure", "status": "False", "reason": "KubeletHasNoDiskPressure", "message": "kubelet has no disk pressure", "lastHeartbeatTime": now, "lastTransitionTime": tsAgo(30 * 24 * time.Hour)},
				map[string]interface{}{"type": "PIDPressure", "status": "False", "reason": "KubeletHasSufficientPID", "message": "kubelet has sufficient PID available", "lastHeartbeatTime": now, "lastTransitionTime": tsAgo(30 * 24 * time.Hour)},
				map[string]interface{}{"type": "Ready", "status": "True", "reason": "KubeletReady", "message": "kubelet is posting ready status", "lastHeartbeatTime": now, "lastTransitionTime": tsAgo(29 * 24 * time.Hour)},
			},
			"addresses": []interface{}{
				map[string]interface{}{"address": "192.168.1.10", "type": "InternalIP"},
				map[string]interface{}{"address": name, "type": "Hostname"},
			},
			"daemonEndpoints": map[string]interface{}{"kubeletEndpoint": map[string]interface{}{"Port": 10250}},
			"nodeInfo": map[string]interface{}{
				"architecture":            "amd64",
				"bootID":                  newUUID(),
				"containerRuntimeVersion": "containerd://1.7.24",
				"kernelVersion":           "5.4.0-216-generic",
				"kubeProxyVersion":        cfg.version(),
				"kubeletVersion":          cfg.version(),
				"machineID":               randomHex(32),
				"operatingSystem":         "linux",
				"osImage":                 "Ubuntu 22.04.3 LTS",
				"systemUUID":              newUUID(),
			},
			"images": []interface{}{
				map[string]interface{}{"names": []interface{}{"nginx@sha256:" + randomHex(64)}, "sizeBytes": int64(187000000)},
			},
		},
	}
}

func podObject(name, ns, image, phase string, restarts int, owner map[string]interface{}, idx int) map[string]interface{} {
	ts := tsAgo(time.Duration(2+idx) * time.Hour)
	ready := phase == "Running"
	containerName := strings.SplitN(strings.TrimPrefix(image, "docker.io/library/"), ":", 2)[0]
	containerName = containerName[strings.LastIndex(containerName, "/")+1:]
	meta := map[string]interface{}{
		"name":              name,
		"namespace":         ns,
		"creationTimestamp": ts,
		"labels":            map[string]interface{}{"app": containerName, "pod-template-hash": hashSuffix(name)},
	}
	if owner != nil {
		meta["ownerReferences"] = []interface{}{owner}
	}
	status := map[string]interface{}{
		"phase":     phase,
		"hostIP":    "192.168.1.10",
		"podIP":     fmt.Sprintf("10.244.1.%d", 10+idx),
		"podIPs":    []interface{}{map[string]interface{}{"ip": fmt.Sprintf("10.244.1.%d", 10+idx)}},
		"qosClass":  "BestEffort",
		"startTime": ts,
	}
	containerStatus := map[string]interface{}{
		"name":         containerName,
		"image":        image,
		"imageID":      "docker.io/library/" + containerName + "@sha256:" + randomHex(64),
		"containerID":  "containerd://" + randomHex(64),
		"ready":        ready,
		"restartCount": restarts,
		"started":      ready,
		"state":        map[string]interface{}{"running": map[string]interface{}{"startedAt": ts}},
		"lastState":    map[string]interface{}{},
	}
	if restarts > 0 {
		containerStatus["state"] = map[string]interface{}{"waiting": map[string]interface{}{"message": "back-off 5m0s restarting failed container=" + containerName, "reason": "CrashLoopBackOff"}}
		containerStatus["ready"] = false
		containerStatus["started"] = false
		containerStatus["lastState"] = map[string]interface{}{
			"terminated": map[string]interface{}{"containerID": "containerd://" + randomHex(64), "exitCode": 1, "finishedAt": tsAgo(10 * time.Minute), "reason": "Error", "startedAt": tsAgo(12 * time.Minute)},
		}
		status["phase"] = "Running"
	}
	status["containerStatuses"] = []interface{}{containerStatus}
	status["conditions"] = []interface{}{
		map[string]interface{}{"type": "Initialized", "status": "True", "lastProbeTime": nil, "lastTransitionTime": ts, "reason": "ContainersReady"},
		map[string]interface{}{"type": "Ready", "status": boolStatus(ready), "lastProbeTime": nil, "lastTransitionTime": ts},
		map[string]interface{}{"type": "ContainersReady", "status": boolStatus(ready), "lastProbeTime": nil, "lastTransitionTime": ts},
		map[string]interface{}{"type": "PodScheduled", "status": "True", "lastProbeTime": nil, "lastTransitionTime": ts},
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   meta,
		"spec": map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{
				"name":                     containerName,
				"image":                    image,
				"imagePullPolicy":          "IfNotPresent",
				"ports":                    []interface{}{map[string]interface{}{"containerPort": 80, "protocol": "TCP"}},
				"resources":                map[string]interface{}{},
				"terminationMessagePath":   "/dev/termination-log",
				"terminationMessagePolicy": "File",
			}},
			"dnsPolicy":                     "ClusterFirst",
			"enableServiceLinks":            true,
			"nodeName":                      "node-1",
			"preemptionPolicy":              "PreemptLowerPriority",
			"priority":                      0,
			"restartPolicy":                 "Always",
			"schedulerName":                 "default-scheduler",
			"securityContext":               map[string]interface{}{},
			"serviceAccount":                "default",
			"serviceAccountName":            "default",
			"terminationGracePeriodSeconds": 30,
		},
		"status": status,
	}
}

func boolStatus(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func hashSuffix(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return "7d8f9c6b5"
}

func ownerRefForPod(ns, podName string) map[string]interface{} {
	parts := strings.Split(podName, "-")
	if len(parts) < 3 {
		return nil
	}
	rsName := strings.Join(parts[:len(parts)-1], "-")
	app := parts[0]
	return map[string]interface{}{
		"apiVersion":         "apps/v1",
		"kind":               "ReplicaSet",
		"name":               rsName,
		"uid":                newUUID(),
		"controller":         true,
		"blockOwnerDeletion": true,
		"labels":             map[string]interface{}{"app": app},
	}
}

func deploymentObject(name, ns, app, image string, replicas, ready int, hash string) map[string]interface{} {
	ts := tsAgo(26 * time.Hour)
	podLabels := map[string]interface{}{"app": app}
	return map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":              name,
			"namespace":         ns,
			"uid":               newUUID(),
			"generation":        1,
			"creationTimestamp": ts,
			"labels":            podLabels,
			"annotations":       map[string]interface{}{"deployment.kubernetes.io/revision": "1"},
		},
		"spec": map[string]interface{}{
			"replicas":                replicas,
			"revisionHistoryLimit":    10,
			"progressDeadlineSeconds": 600,
			"selector":                map[string]interface{}{"matchLabels": podLabels},
			"strategy": map[string]interface{}{
				"type":          "RollingUpdate",
				"rollingUpdate": map[string]interface{}{"maxSurge": "25%", "maxUnavailable": "25%"},
			},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{"labels": map[string]interface{}{"app": app, "pod-template-hash": hash}},
				"spec": map[string]interface{}{
					"containers": []interface{}{map[string]interface{}{
						"name":            name,
						"image":           image,
						"imagePullPolicy": "IfNotPresent",
						"ports":           []interface{}{map[string]interface{}{"containerPort": 80, "protocol": "TCP"}},
						"resources":       map[string]interface{}{},
					}},
					"dnsPolicy":                     "ClusterFirst",
					"restartPolicy":                 "Always",
					"schedulerName":                 "default-scheduler",
					"securityContext":               map[string]interface{}{},
					"terminationGracePeriodSeconds": 30,
				},
			},
		},
		"status": map[string]interface{}{
			"observedGeneration": 1,
			"replicas":           replicas,
			"updatedReplicas":    replicas,
			"readyReplicas":      ready,
			"availableReplicas":  ready,
			"conditions": []interface{}{
				map[string]interface{}{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "message": "Deployment has minimum availability.", "lastTransitionTime": ts, "lastUpdateTime": ts},
				map[string]interface{}{"type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable", "message": fmt.Sprintf("ReplicaSet %q has successfully progressed.", name+"-"+hash), "lastTransitionTime": ts, "lastUpdateTime": ts},
			},
		},
	}
}

func replicaSetObject(name, ns, app, image string, replicas int, hash string) map[string]interface{} {
	ts := tsAgo(26 * time.Hour)
	podLabels := map[string]interface{}{"app": app, "pod-template-hash": hash}
	return map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "ReplicaSet",
		"metadata": map[string]interface{}{
			"name":              name,
			"namespace":         ns,
			"generation":        1,
			"creationTimestamp": ts,
			"labels":            podLabels,
			"annotations":       map[string]interface{}{"deployment.kubernetes.io/desired-replicas": strconv.Itoa(replicas), "deployment.kubernetes.io/max-replicas": strconv.Itoa(replicas + 1), "deployment.kubernetes.io/revision": "1"},
			"ownerReferences": []interface{}{map[string]interface{}{
				"apiVersion": "apps/v1", "kind": "Deployment", "name": strings.TrimSuffix(name, "-"+hash), "controller": true, "blockOwnerDeletion": true,
			}},
		},
		"spec": map[string]interface{}{
			"replicas": replicas,
			"selector": map[string]interface{}{"matchLabels": podLabels},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{"labels": podLabels},
				"spec": map[string]interface{}{
					"containers": []interface{}{map[string]interface{}{
						"name": strings.TrimSuffix(name, "-"+hash), "image": image, "imagePullPolicy": "IfNotPresent",
					}},
					"dnsPolicy":     "ClusterFirst",
					"restartPolicy": "Always",
				},
			},
		},
		"status": map[string]interface{}{
			"observedGeneration":   1,
			"replicas":             replicas,
			"fullyLabeledReplicas": replicas,
			"readyReplicas":        replicas,
			"availableReplicas":    replicas,
		},
	}
}

func serviceObject(name, ns, clusterIP string, port int, portName, protocol string, target int, selector map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name":              name,
			"namespace":         ns,
			"creationTimestamp": tsAgo(26 * time.Hour),
			"labels":            selector,
		},
		"spec": map[string]interface{}{
			"clusterIP":             clusterIP,
			"clusterIPs":            []interface{}{clusterIP},
			"internalTrafficPolicy": "Cluster",
			"ipFamilies":            []interface{}{"IPv4"},
			"ipFamilyPolicy":        "SingleStack",
			"ports": []interface{}{map[string]interface{}{
				"name": portName, "port": port, "protocol": protocol, "targetPort": target,
			}},
			"selector":        selector,
			"sessionAffinity": "None",
			"type":            "ClusterIP",
		},
		"status": map[string]interface{}{"loadBalancer": map[string]interface{}{}},
	}
}

func endpointsObject(name, ns, ip, portName string, port int, protocol string) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Endpoints",
		"metadata": map[string]interface{}{
			"name": name, "namespace": ns, "creationTimestamp": tsAgo(26 * time.Hour),
		},
		"subsets": []interface{}{map[string]interface{}{
			"addresses": []interface{}{map[string]interface{}{"ip": ip, "nodeName": "node-1"}},
			"ports":     []interface{}{map[string]interface{}{"name": portName, "port": port, "protocol": protocol}},
		}},
	}
}

func eventObject(kind, objName, ns, reason, message, component, eventType string) map[string]interface{} {
	ts := tsAgo(2 * time.Hour)
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata": map[string]interface{}{
			"name":              objName + "." + randomHex(16),
			"namespace":         ns,
			"creationTimestamp": ts,
		},
		"involvedObject":     map[string]interface{}{"kind": kind, "namespace": ns, "name": objName, "apiVersion": "v1"},
		"reason":             reason,
		"message":            message,
		"source":             map[string]interface{}{"component": component},
		"firstTimestamp":     ts,
		"lastTimestamp":      ts,
		"count":              1,
		"type":               eventType,
		"eventTime":          nil,
		"reportingComponent": "",
		"reportingInstance":  "",
	}
}

func daemonSetObject() map[string]interface{} {
	ts := tsAgo(26 * time.Hour)
	sel := map[string]interface{}{"k8s-app": "kube-proxy"}
	return map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "DaemonSet",
		"metadata": map[string]interface{}{
			"name": "kube-proxy", "namespace": "kube-system", "generation": 1, "creationTimestamp": ts,
			"labels": sel,
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{"matchLabels": sel},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{"labels": sel},
				"spec": map[string]interface{}{
					"containers": []interface{}{map[string]interface{}{
						"name": "kube-proxy", "image": "registry.k8s.io/kube-proxy:v1.28.4", "imagePullPolicy": "IfNotPresent",
					}},
					"hostNetwork":     true,
					"restartPolicy":   "Always",
					"securityContext": map[string]interface{}{},
				},
			},
		},
		"status": map[string]interface{}{
			"observedGeneration":     1,
			"desiredNumberScheduled": 1,
			"currentNumberScheduled": 1,
			"numberReady":            1,
			"updatedNumberScheduled": 1,
			"numberAvailable":        1,
		},
	}
}

func ingressObject() map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata": map[string]interface{}{
			"name": "nginx", "namespace": "default", "creationTimestamp": tsAgo(20 * time.Hour),
			"annotations": map[string]interface{}{"nginx.ingress.kubernetes.io/rewrite-target": "/"},
		},
		"spec": map[string]interface{}{
			"ingressClassName": "nginx",
			"rules": []interface{}{map[string]interface{}{
				"host": "app.example.com",
				"http": map[string]interface{}{"paths": []interface{}{map[string]interface{}{
					"backend":  map[string]interface{}{"service": map[string]interface{}{"name": "nginx", "port": map[string]interface{}{"number": 80}}},
					"path":     "/",
					"pathType": "Prefix",
				}}},
			}},
		},
		"status": map[string]interface{}{"loadBalancer": map[string]interface{}{}},
	}
}

func fakeCACert() string {
	return "-----BEGIN CERTIFICATE-----\nMIIDBTCCAe2gAwIBAgIIUu0m1FJ1q2UwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UE\nAxMKa3ViZXJuZXRlczAeFw0yMzAxMDEwMDAwMDBaFw0zMzAxMDEwMDAwMDBaMBUx\nEzARBgNVBAMTCmt1YmVybmV0ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7Z2sWn6mCq0J0m9t2f0mK1vQ0h2s0P0o8wW1jF0Zj0l6oQn1y0mZ0qk3K\n-----END CERTIFICATE-----\n"
}

// ---- 连接处理 ----

func k8sHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(kubernetesConfig)
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Errorln(err)
		service.ReportError(err)
		return
	}
	defer listen.Close()

	// Kubernetes API Server 必须 HTTPS；证书优先从文件加载，缺失则自动生成自签证书。
	cert, err := common.LoadOrGenCert(cfg.CertFile, cfg.KeyFile, baseOptions.Application)
	if err != nil {
		logger.Log.Fatalf("加载/生成 TLS 证书失败: %v", err)
	}
	tlsConf := common.NewServerTLSConfig(cert)

	logger.Log.Infof("%s listen on %s (https)", baseOptions.Application, address)


	service.MarkReady()

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleConn(conn, service, cfg, tlsConf)
		}
	}
}

func handleConn(conn net.Conn, service *services.Service, cfg kubernetesConfig, tlsConf *tls.Config) {
	defer conn.Close()
	baseOptions := service.BaseOptions
	cfg.store.ensureSeeded(cfg)

	// 先作为 TLS 服务端握手（K8s API 必须加密）
	tlsConn := tls.Server(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		logger.Log.Debug(serviceName, " tls handshake failed:", err)
		return
	}
	conn = net.Conn(tlsConn)

	id := xid.New()
	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "k8s-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":       baseOptions.Protocol,
		"application":    baseOptions.Application,
		"k8s.session-id": id.String(),
		"k8s.version":    cfg.version(),
	}))

	pushClose := func() {
		event.EventPush(event.NewEvent(serviceName, "k8s-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":       baseOptions.Protocol,
			"application":    baseOptions.Application,
			"k8s.session-id": id.String(),
		}))
	}

	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.idleTimeout()))
		req, err := http.ReadRequest(reader)
		if err != nil {
			pushClose()
			return
		}
		body := readK8sBody(req)
		handleRequest(conn, req, service, cfg, id, srcAddr, dstAddr, body)
	}
}

func readK8sBody(req *http.Request) []byte {
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

func handleRequest(conn net.Conn, req *http.Request, service *services.Service, cfg kubernetesConfig,
	id xid.ID, srcAddr, dstAddr common.Addr, body []byte) {
	baseOptions := service.BaseOptions
	path := req.URL.Path

	details := map[string]interface{}{
		"protocol":           baseOptions.Protocol,
		"application":        baseOptions.Application,
		"k8s.session-id":     id.String(),
		"k8s.method":         req.Method,
		"k8s.url":            req.URL.String(),
		"k8s.path":           path,
		"k8s.query":          req.URL.RawQuery,
		"k8s.host":           req.Host,
		"k8s.user_agent":     req.UserAgent(),
		"k8s.content_length": req.ContentLength,
		"k8s.body":           string(body),
	}
	if auth := req.Header.Get("Authorization"); auth != "" {
		details["k8s.authorization"] = auth
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			details["k8s.token"] = strings.TrimSpace(auth[len(prefix):])
		}
	}
	event.EventPush(event.NewEvent(serviceName, "k8s-request", srcAddr, dstAddr, details))

	route(conn, req, cfg, path, body)
}

// ---- 路由 ----

func route(conn net.Conn, req *http.Request, cfg kubernetesConfig, path string, body []byte) {
	segs := splitPath(path)
	if len(segs) == 0 {
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	}
	switch segs[0] {
	case "version":
		respondJSON(conn, req, http.StatusOK, versionInfo(cfg))
		return
	case "healthz", "readyz", "livez":
		respondText(conn, req, http.StatusOK, "ok")
		return
	case "metrics":
		respondText(conn, req, http.StatusOK, metricsText())
		return
	case "openapi":
		// 真机提供完整 OpenAPI（protobuf），蜜罐不提供 schema：
		// kubectl apply 默认校验会失败，加 --validate=false 可正常创建/更新。
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	case "swagger-2.0.0.pb-v1", "swagger-2.0.0.pb-v1.gz":
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	case "api":
		if len(segs) == 1 {
			respondJSON(conn, req, http.StatusOK, map[string]interface{}{
				"kind":     "APIVersions",
				"versions": []string{"v1"},
				"serverAddressByClientCIDRs": []map[string]interface{}{
					{"clientCIDR": "0.0.0.0/0", "serverAddress": req.Host},
				},
			})
			return
		}
		if segs[1] != "v1" {
			respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
			return
		}
		if len(segs) == 2 {
			respondJSON(conn, req, http.StatusOK, apiResourceList("", "v1"))
			return
		}
		handleResource(conn, req, cfg, "", "v1", segs[2:], body)
		return
	case "apis":
		if len(segs) == 1 {
			respondJSON(conn, req, http.StatusOK, apiGroupList())
			return
		}
		if len(segs) == 2 {
			if g, ok := findGroup(segs[1]); ok {
				respondJSON(conn, req, http.StatusOK, apiGroup(g.name, g.versions))
				return
			}
			respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
			return
		}
		if len(segs) == 3 {
			if _, ok := findGroup(segs[1]); !ok {
				respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
				return
			}
			respondJSON(conn, req, http.StatusOK, apiResourceList(segs[1], segs[2]))
			return
		}
		if _, ok := findGroup(segs[1]); !ok {
			respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
			return
		}
		// 授权/认证相关 group 走专用处理
		if segs[1] == "authorization.k8s.io" || segs[1] == "authentication.k8s.io" {
			handleAuthAPI(conn, req, segs[1], segs[3:], body)
			return
		}
		// 指标数据（kubectl top）走专用处理
		if segs[1] == "metrics.k8s.io" {
			handleMetricsAPI(conn, req, cfg, segs[2:])
			return
		}
		handleResource(conn, req, cfg, segs[1], segs[2], segs[3:], body)
		return
	}
	respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
}

func findGroup(name string) (struct {
	name     string
	versions []string
}, bool) {
	for _, g := range apiGroups {
		if g.name == name {
			return g, true
		}
	}
	return struct {
		name     string
		versions []string
	}{}, false
}

// handleResource 处理 /api/v1/<rest> 或 /apis/<group>/<version>/<rest>。
func handleResource(conn net.Conn, req *http.Request, cfg kubernetesConfig, group, version string, segs []string, body []byte) {
	if len(segs) == 0 {
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	}
	var ns, resName, objName, sub string
	if segs[0] == "namespaces" {
		switch {
		case len(segs) == 1:
			resName = "namespaces"
		case len(segs) == 2:
			resName, objName = "namespaces", segs[1]
		default:
			ns = segs[1]
			resName = segs[2]
			if len(segs) >= 4 {
				objName = segs[3]
			}
			if len(segs) >= 5 {
				sub = segs[4]
			}
		}
	} else {
		resName = segs[0]
		if len(segs) >= 2 {
			objName = segs[1]
		}
		if len(segs) >= 3 {
			sub = segs[2]
		}
	}

	def, ok := findResourceDef(group, version, resName)
	if !ok {
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	}
	// 命名空间路径访问非命名空间资源 / 反之，按 404 处理
	if ns != "" && !def.namespaced {
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	}

	// 子资源
	if sub != "" && objName != "" {
		switch sub {
		case "log":
			handlePodLog(conn, req, cfg, def, ns, objName)
			return
		case "status", "scale", "proxy":
			handleSubresource(conn, req, cfg, def, ns, objName, sub, body)
			return
		case "exec", "attach", "portforward":
			// SPDY/WebSocket 升级不实现；真机在无 Upgrade 头时也回 400
			respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "Upgrade request required", nil)
			return
		default:
			respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
			return
		}
	}

	store := cfg.store
	labelSel := req.URL.Query().Get("labelSelector")
	fieldSel := req.URL.Query().Get("fieldSelector")

	switch req.Method {
	case http.MethodGet:
		if boolQuery(req.URL.Query().Get("watch")) {
			handleWatch(conn, req, cfg, def, ns, labelSel, fieldSel)
			return
		}
		store.mu.Lock()
		if objName != "" {
			obj, found := store.getLocked(group, def.name, ns, objName)
			rv := strconv.FormatInt(store.rv, 10)
			store.mu.Unlock()
			if !found {
				respondStatus(conn, req, http.StatusNotFound, "NotFound",
					fmt.Sprintf("%s %q not found", def.name, objName),
					map[string]interface{}{"name": objName, "kind": def.name})
				return
			}
			if wantsTable(req) {
				respondJSON(conn, req, http.StatusOK, buildTable(def, []map[string]interface{}{obj}, rv))
				return
			}
			respondJSON(conn, req, http.StatusOK, obj)
			return
		}
		items := filterItems(store.listLocked(group, def.name, ns, ns == "" && def.namespaced), labelSel, fieldSel)
		rv := strconv.FormatInt(store.rv, 10)
		store.mu.Unlock()
		items, continueToken := applyLimit(items, req.URL.Query().Get("limit"), req.URL.Query().Get("continue"))
		if wantsTable(req) {
			table := buildTable(def, items, rv)
			if continueToken != "" {
				table["metadata"].(map[string]interface{})["continue"] = continueToken
			}
			respondJSON(conn, req, http.StatusOK, table)
			return
		}
		resp := map[string]interface{}{
			"kind":       def.kind + "List",
			"apiVersion": def.apiVersion(),
			"metadata":   map[string]interface{}{"resourceVersion": rv},
			"items":      items,
		}
		if continueToken != "" {
			resp["metadata"].(map[string]interface{})["continue"] = continueToken
		}
		respondJSON(conn, req, http.StatusOK, resp)
		return
	case http.MethodPost:
		obj := decodeObject(req, body)
		if obj == nil {
			respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "the object provided is unrecognized or invalid", nil)
			return
		}
		store.mu.Lock()
		name := objectName(obj)
		if name == "" {
			name = generateName(obj)
		}
		if name == "" {
			store.mu.Unlock()
			respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "metadata.name: Required value: name or generateName is required", nil)
			return
		}
		if def.namespaced {
			if ns == "" {
				ns = "default"
			}
			if _, ok := store.getLocked("", "namespaces", "", ns); !ok {
				store.mu.Unlock()
				respondStatus(conn, req, http.StatusNotFound, "NotFound",
					fmt.Sprintf("namespaces %q not found", ns), map[string]interface{}{"name": ns, "kind": "namespaces"})
				return
			}
		}
		if _, exists := store.getLocked(group, def.name, ns, name); exists {
			store.mu.Unlock()
			respondStatus(conn, req, http.StatusConflict, "AlreadyExists",
				fmt.Sprintf("%s %q already exists", def.name, name),
				map[string]interface{}{"name": name, "kind": def.name})
			return
		}
		if _, ok := obj["kind"]; !ok {
			obj["kind"] = def.kind
		}
		if _, ok := obj["apiVersion"]; !ok {
			obj["apiVersion"] = def.apiVersion()
		}
		initObjectDefaults(def, obj)
		store.putLocked(group, def.name, ns, name, obj)
		store.mu.Unlock()
		respondJSON(conn, req, http.StatusCreated, obj)
		return
	case http.MethodPut:
		obj := decodeObject(req, body)
		if obj == nil || objName == "" {
			respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "the object provided is unrecognized or invalid", nil)
			return
		}
		store.mu.Lock()
		old, found := store.getLocked(group, def.name, ns, objName)
		if !found {
			store.mu.Unlock()
			respondStatus(conn, req, http.StatusNotFound, "NotFound",
				fmt.Sprintf("%s %q not found", def.name, objName), map[string]interface{}{"name": objName, "kind": def.name})
			return
		}
		if rv, _ := objectRV(obj); rv != "" {
			if cur, _ := objectRV(old); rv != cur {
				store.mu.Unlock()
				respondStatus(conn, req, http.StatusConflict, "Conflict",
					fmt.Sprintf("Operation cannot be fulfilled on %s %q: the object has been modified; please apply your changes to the latest version and try again", def.name, objName), nil)
				return
			}
		}
		store.putLocked(group, def.name, ns, objName, obj)
		store.mu.Unlock()
		respondJSON(conn, req, http.StatusOK, obj)
		return
	case http.MethodPatch:
		handlePatch(conn, req, cfg, def, group, ns, objName, body)
		return
	case http.MethodDelete:
		store.mu.Lock()
		if objName != "" {
			obj, found := store.getLocked(group, def.name, ns, objName)
			if !found {
				store.mu.Unlock()
				respondStatus(conn, req, http.StatusNotFound, "NotFound",
					fmt.Sprintf("%s %q not found", def.name, objName), map[string]interface{}{"name": objName, "kind": def.name})
				return
			}
			delete(store.objects, objKey(group, def.name, ns, objName))
			store.rv++
			store.mu.Unlock()
			respondJSON(conn, req, http.StatusOK, obj)
			return
		}
		// deletecollection
		deleted := make([]map[string]interface{}, 0)
		for k, obj := range store.objects {
			parts := strings.SplitN(k, "|", 4)
			if len(parts) == 4 && parts[0] == group && parts[1] == def.name && parts[2] == ns {
				deleted = append(deleted, obj)
				delete(store.objects, k)
			}
		}
		store.rv++
		store.mu.Unlock()
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"kind": def.kind + "List", "apiVersion": def.apiVersion(),
			"metadata": map[string]interface{}{"resourceVersion": "0"}, "items": deleted,
		})
		return
	}
	// 方法不允许
	conn.Write([]byte(fmt.Sprintf("%s 405 Method Not Allowed\r\nAllow: GET, POST, PUT, PATCH, DELETE\r\nContent-Length: 0\r\n\r\n", req.Proto)))
}

// handlePatch 处理 PATCH（merge-patch / strategic-merge / apply-patch+yaml）。
func handlePatch(conn net.Conn, req *http.Request, cfg kubernetesConfig, def resourceDef, group, ns, objName string, body []byte) {
	if objName == "" {
		respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "patch requires a resource name", nil)
		return
	}
	ct := req.Header.Get("Content-Type")
	patch := map[string]interface{}{}
	var err error
	if strings.Contains(ct, "yaml") {
		err = yaml.Unmarshal(body, &patch)
	} else {
		err = json.Unmarshal(body, &patch)
	}
	if err != nil || len(patch) == 0 {
		respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "the body of the request was in an unknown format", nil)
		return
	}
	apply := strings.Contains(ct, "apply-patch")

	store := cfg.store
	store.mu.Lock()
	defer store.mu.Unlock()
	old, found := store.getLocked(group, def.name, ns, objName)
	if !found {
		if !apply {
			respondStatus(conn, req, http.StatusNotFound, "NotFound",
				fmt.Sprintf("%s %q not found", def.name, objName), map[string]interface{}{"name": objName, "kind": def.name})
			return
		}
		// kubectl apply：不存在则创建
		if _, ok := patch["kind"]; !ok {
			patch["kind"] = def.kind
		}
		if _, ok := patch["apiVersion"]; !ok {
			patch["apiVersion"] = def.apiVersion()
		}
		if def.namespaced {
			if ns == "" {
				ns = "default"
			}
			if _, ok := store.getLocked("", "namespaces", "", ns); !ok {
				respondStatus(conn, req, http.StatusNotFound, "NotFound",
					fmt.Sprintf("namespaces %q not found", ns), map[string]interface{}{"name": ns, "kind": "namespaces"})
				return
			}
		}
		store.putLocked(group, def.name, ns, objName, patch)
		respondJSON(conn, req, http.StatusCreated, patch)
		return
	}
	merged := mergePatch(old, patch)
	store.putLocked(group, def.name, ns, objName, merged)
	respondJSON(conn, req, http.StatusOK, merged)
}

// handleWatch 以 chunked 流下发已有对象（ADDED），随后保持连接直到超时/断开。
func handleWatch(conn net.Conn, req *http.Request, cfg kubernetesConfig, def resourceDef, ns, labelSel, fieldSel string) {
	store := cfg.store
	store.mu.Lock()
	items := filterItems(store.listLocked(def.group, def.name, ns, ns == "" && def.namespaced), labelSel, fieldSel)
	store.mu.Unlock()

	head := fmt.Sprintf("%s 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache, private\r\nAudit-Id: %s\r\nTransfer-Encoding: chunked\r\n\r\n",
		req.Proto, newUUID())
	if _, err := conn.Write([]byte(head)); err != nil {
		return
	}
	for _, item := range items {
		b, err := json.Marshal(map[string]interface{}{"type": "ADDED", "object": item})
		if err != nil {
			continue
		}
		if err := writeChunk(conn, b); err != nil {
			return
		}
	}
	timeout := 300 * time.Second
	if v := req.URL.Query().Get("timeoutSeconds"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return // 客户端关闭
		}
	}
	_, _ = conn.Write([]byte("0\r\n\r\n"))
}

// writeChunk 写一个 HTTP chunk。
func writeChunk(w io.Writer, data []byte) error {
	if _, err := fmt.Fprintf(w, "%x\r\n", len(data)); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err := w.Write([]byte("\r\n"))
	return err
}

// handleSubresource 处理 status / scale / proxy 子资源。
func handleSubresource(conn net.Conn, req *http.Request, cfg kubernetesConfig, def resourceDef, ns, objName, sub string, body []byte) {
	store := cfg.store
	store.mu.Lock()
	defer store.mu.Unlock()
	obj, found := store.getLocked(def.group, def.name, ns, objName)
	if !found {
		respondStatus(conn, req, http.StatusNotFound, "NotFound",
			fmt.Sprintf("%s %q not found", def.name, objName), map[string]interface{}{"name": objName, "kind": def.name})
		return
	}
	switch sub {
	case "status":
		switch req.Method {
		case http.MethodGet:
			respondJSON(conn, req, http.StatusOK, obj)
		case http.MethodPut, http.MethodPatch:
			if patch := decodeObject(req, body); patch != nil {
				if st, ok := patch["status"]; ok {
					obj["status"] = st
				}
				store.putLocked(def.group, def.name, ns, objName, obj)
			}
			respondJSON(conn, req, http.StatusOK, obj)
		default:
			respondStatus(conn, req, http.StatusMethodNotAllowed, "MethodNotAllowed", "the server does not allow this method on the requested resource", nil)
		}
	case "scale":
		meta, _ := obj["metadata"].(map[string]interface{})
		scale := map[string]interface{}{
			"kind":       "Scale",
			"apiVersion": "autoscaling/v1",
			"metadata":   meta,
			"spec":       map[string]interface{}{"replicas": currentReplicas(obj)},
			"status":     map[string]interface{}{"replicas": currentReplicas(obj)},
		}
		switch req.Method {
		case http.MethodGet:
			respondJSON(conn, req, http.StatusOK, scale)
		case http.MethodPut, http.MethodPatch:
			patch := decodeObject(req, body)
			if patch == nil {
				respondStatus(conn, req, http.StatusBadRequest, "BadRequest", "the object provided is unrecognized or invalid", nil)
				return
			}
			if spec, ok := patch["spec"].(map[string]interface{}); ok {
				if r, ok := spec["replicas"].(float64); ok {
					specObj, _ := obj["spec"].(map[string]interface{})
					if specObj == nil {
						specObj = map[string]interface{}{}
						obj["spec"] = specObj
					}
					specObj["replicas"] = int(r)
					if st, ok := obj["status"].(map[string]interface{}); ok {
						st["replicas"] = int(r)
					}
					store.putLocked(def.group, def.name, ns, objName, obj)
					scale["spec"] = map[string]interface{}{"replicas": int(r)}
					scale["status"] = map[string]interface{}{"replicas": int(r)}
				}
			}
			respondJSON(conn, req, http.StatusOK, scale)
		default:
			respondStatus(conn, req, http.StatusMethodNotAllowed, "MethodNotAllowed", "the server does not allow this method on the requested resource", nil)
		}
	case "proxy":
		respondText(conn, req, http.StatusOK, "")
	}
}

func currentReplicas(obj map[string]interface{}) int {
	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if r, ok := spec["replicas"].(float64); ok {
			return int(r)
		}
		if r, ok := spec["replicas"].(int); ok {
			return r
		}
	}
	return 1
}

// handlePodLog 返回 Pod 日志（纯文本，按镜像给不同内容）。
func handlePodLog(conn net.Conn, req *http.Request, cfg kubernetesConfig, def resourceDef, ns, name string) {
	if def.name != "pods" {
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	}
	store := cfg.store
	store.mu.Lock()
	obj, found := store.getLocked("", "pods", ns, name)
	store.mu.Unlock()
	if !found {
		respondStatus(conn, req, http.StatusNotFound, "NotFound",
			fmt.Sprintf("pods %q not found", name), map[string]interface{}{"name": name, "kind": "pods"})
		return
	}
	image := ""
	containers, _ := obj["spec"].(map[string]interface{})["containers"].([]interface{})
	if len(containers) > 0 {
		if cm, ok := containers[0].(map[string]interface{}); ok {
			image, _ = cm["image"].(string)
		}
	}
	text := podLogText(image, name)
	// tailLines / sinceSeconds 常见参数：tail 取末尾 N 行
	if tail := req.URL.Query().Get("tailLines"); tail != "" {
		if n, err := strconv.Atoi(tail); err == nil && n > 0 {
			lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			if len(lines) > n {
				lines = lines[len(lines)-n:]
			}
			text = strings.Join(lines, "\n") + "\n"
		}
	}
	respondText(conn, req, http.StatusOK, text)
}

// podLogText 按镜像给出一段可信日志（kubectl logs 输出）。
func podLogText(image, podName string) string {
	switch {
	case strings.Contains(image, "nginx"):
		return "2026/10/20 09:00:00 [notice] 1#1: using the \"epoll\" event method\n" +
			"2026/10/20 09:00:00 [notice] 1#1: nginx/1.25.3\n" +
			"2026/10/20 09:00:00 [notice] 1#1: start worker processes\n" +
			"10.244.1.1 - - [20/Oct/2026:09:01:12 +0000] \"GET /healthz HTTP/1.1\" 200 2 \"-\" \"kube-probe/1.28\"\n"
	case strings.Contains(image, "redis"):
		return "1:M 20 Oct 2026 09:00:00.123 * Running mode=standalone, port=6379.\n" +
			"1:M 20 Oct 2026 09:00:00.124 # Server initialized\n" +
			"1:M 20 Oct 2026 09:00:00.130 * Ready to accept connections tcp\n"
	case strings.Contains(image, "coredns"):
		return ".:53\n[INFO] plugin/reload: Running configuration SHA512 = 5f8f1c2d9e0b\n" +
			"CoreDNS-1.10.1\nlinux/amd64, go1.20.7, 1c8b8f8\n"
	case strings.Contains(image, "etcd"):
		return "{\"level\":\"info\",\"ts\":\"2026-10-20T09:00:00.120Z\",\"caller\":\"embed/etcd.go:127\",\"msg\":\"serving client traffic insecurely; this is strongly discouraged!\"}\n" +
			"{\"level\":\"info\",\"ts\":\"2026-10-20T09:00:01.340Z\",\"caller\":\"embed/etcd.go:309\",\"msg\":\"ready to serve client requests\"}\n"
	case strings.Contains(image, "kube-apiserver"):
		return "I1020 09:00:00.120000       1 parser.go:183] parsing go.mod\n" +
			"I1020 09:00:02.450000       1 server.go:619] External client cert verified\n" +
			"I1020 09:00:02.460000       1 serving.go:348] Generated self-signed cert in-memory\n"
	case strings.Contains(image, "kube-controller-manager"):
		return "I1020 09:00:00.100000       1 serving.go:348] Generated self-signed cert in-memory\n" +
			"I1020 09:00:01.220000       1 controllermanager.go:246] Started controller: \"deployment-controller\"\n"
	case strings.Contains(image, "kube-scheduler"):
		return "I1020 09:00:00.100000       1 serving.go:348] Generated self-signed cert in-memory\n" +
			"I1020 09:00:01.310000       1 server.go:154] Starting Kubernetes Scheduler version v1.28.4\n"
	case strings.Contains(image, "kube-proxy"):
		return "I1020 09:00:00.100000       1 server_linux.go:66] Using iptables Proxier.\n" +
			"I1020 09:00:00.210000       1 server.go:234] Starting kube-proxy version v1.28.4\n"
	case strings.Contains(image, "broken-app"):
		return "2026-10-20T09:00:00Z ERROR failed to connect to database: dial tcp 10.96.55.10:5432: i/o timeout\n" +
			"2026-10-20T09:00:05Z FATAL giving up after 6 attempts\n"
	}
	return "2026-10-20T09:00:00Z INFO " + podName + " started\n"
}

// handleMetricsAPI metrics.k8s.io（kubectl top 用）。
func handleMetricsAPI(conn net.Conn, req *http.Request, cfg kubernetesConfig, segs []string) {
	now := nowTS()
	store := cfg.store
	switch {
	case len(segs) >= 2 && segs[1] == "nodes":
		store.mu.Lock()
		nodes := store.listLocked("", "nodes", "", true)
		store.mu.Unlock()
		if len(segs) >= 3 { // 单个节点
			for _, n := range nodes {
				if objectName(n) == segs[2] {
					respondJSON(conn, req, http.StatusOK, nodeMetrics(n, now))
					return
				}
			}
			respondStatus(conn, req, http.StatusNotFound, "NotFound", fmt.Sprintf("nodes %q not found", segs[2]), nil)
			return
		}
		items := make([]interface{}, 0, len(nodes))
		for _, n := range nodes {
			items = append(items, nodeMetrics(n, now))
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"kind": "NodeMetricsList", "apiVersion": "metrics.k8s.io/v1beta1",
			"metadata": map[string]interface{}{}, "items": items,
		})
	case len(segs) >= 2 && (segs[1] == "pods" || (segs[1] == "namespaces" && len(segs) >= 4 && segs[3] == "pods")):
		ns := ""
		if segs[1] == "namespaces" {
			ns = segs[2]
		}
		store.mu.Lock()
		pods := store.listLocked("", "pods", ns, ns == "")
		store.mu.Unlock()
		items := make([]interface{}, 0, len(pods))
		for _, p := range pods {
			items = append(items, podMetrics(p, now))
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"kind": "PodMetricsList", "apiVersion": "metrics.k8s.io/v1beta1",
			"metadata": map[string]interface{}{}, "items": items,
		})
	default:
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
	}
}

func nodeMetrics(n map[string]interface{}, now string) map[string]interface{} {
	return map[string]interface{}{
		"kind":       "NodeMetrics",
		"apiVersion": "metrics.k8s.io/v1beta1",
		"metadata":   n["metadata"],
		"timestamp":  now,
		"window":     "20.001s",
		"usage":      map[string]interface{}{"cpu": "482m", "memory": "2194520Ki"},
	}
}

func podMetrics(p map[string]interface{}, now string) map[string]interface{} {
	meta, _ := p["metadata"].(map[string]interface{})
	name, _ := meta["name"].(string)
	containers := make([]interface{}, 0, 1)
	if cs, ok := p["spec"].(map[string]interface{})["containers"].([]interface{}); ok {
		for _, c := range cs {
			cm, _ := c.(map[string]interface{})
			cn, _ := cm["name"].(string)
			containers = append(containers, map[string]interface{}{
				"name":  cn,
				"usage": map[string]interface{}{"cpu": "8m", "memory": "32768Ki"},
			})
		}
	}
	return map[string]interface{}{
		"kind":       "PodMetrics",
		"apiVersion": "metrics.k8s.io/v1beta1",
		"metadata":   map[string]interface{}{"name": name, "namespace": meta["namespace"], "creationTimestamp": now},
		"timestamp":  now,
		"window":     "20.001s",
		"containers": containers,
	}
}

// handleAuthAPI 处理 authorization/authentication 组的自查询（一律放行）。
func handleAuthAPI(conn net.Conn, req *http.Request, group string, segs []string, body []byte) {
	if len(segs) == 0 || req.Method != http.MethodPost {
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
		return
	}
	resource := segs[0]
	switch resource {
	case "selfsubjectaccessreviews", "subjectaccessreviews", "localsubjectaccessreviews":
		obj := decodeObject(req, body)
		if obj == nil {
			obj = map[string]interface{}{}
		}
		kind := "SelfSubjectAccessReview"
		if resource == "subjectaccessreviews" {
			kind = "SubjectAccessReview"
		} else if resource == "localsubjectaccessreviews" {
			kind = "LocalSubjectAccessReview"
		}
		obj["kind"] = kind
		obj["apiVersion"] = group + "/v1"
		obj["status"] = map[string]interface{}{"allowed": true, "reason": "RBAC: allowed by ClusterRoleBinding \"cluster-admin\" of ClusterRole \"cluster-admin\""}
		respondJSON(conn, req, http.StatusCreated, obj)
	case "selfsubjectrulesreviews":
		obj := map[string]interface{}{
			"kind": "SelfSubjectRulesReview", "apiVersion": group + "/v1",
			"metadata": map[string]interface{}{"creationTimestamp": nil},
			"spec":     map[string]interface{}{"namespace": "default"},
			"status": map[string]interface{}{
				"resourceRules": []interface{}{
					map[string]interface{}{"apiGroups": []interface{}{"*"}, "resources": []interface{}{"*"}, "verbs": []interface{}{"*"}},
				},
				"nonResourceRules": []interface{}{
					map[string]interface{}{"nonResourceURLs": []interface{}{"*"}, "verbs": []interface{}{"*"}},
				},
				"incomplete": false,
			},
		}
		respondJSON(conn, req, http.StatusCreated, obj)
	case "tokenreviews":
		respondJSON(conn, req, http.StatusCreated, map[string]interface{}{
			"kind": "TokenReview", "apiVersion": group + "/v1",
			"status": map[string]interface{}{
				"authenticated": true,
				"user": map[string]interface{}{
					"username": "admin", "uid": newUUID(),
					"groups": []interface{}{"system:masters", "system:authenticated"},
				},
			},
		})
	default:
		respondStatus(conn, req, http.StatusNotFound, "NotFound", "the server could not find the requested resource", nil)
	}
}

// ---- discovery 响应 ----

func versionInfo(cfg kubernetesConfig) map[string]interface{} {
	ver := strings.TrimPrefix(cfg.version(), "v")
	parts := strings.Split(ver, ".")
	major, minor := "1", "28"
	if len(parts) >= 1 && parts[0] != "" {
		major = parts[0]
	}
	if len(parts) >= 2 && parts[1] != "" {
		minor = parts[1]
	}
	return map[string]interface{}{
		"major":        major,
		"minor":        minor,
		"gitVersion":   cfg.version(),
		"gitCommit":    cfg.gitCommit(),
		"gitTreeState": "clean",
		"buildDate":    cfg.buildDate(),
		"goVersion":    cfg.goVersion(),
		"compiler":     "gc",
		"platform":     cfg.platform(),
	}
}

func apiResourceList(group, version string) map[string]interface{} {
	resources := make([]interface{}, 0)
	for _, d := range defsFor(group, version) {
		r := map[string]interface{}{
			"name":         d.name,
			"singularName": d.singular,
			"namespaced":   d.namespaced,
			"kind":         d.kind,
			"verbs":        defaultVerbs,
		}
		if len(d.shortNames) > 0 {
			r["shortNames"] = d.shortNames
		}
		if len(d.categories) > 0 {
			r["categories"] = d.categories
		}
		resources = append(resources, r)
		switch d.name {
		case "pods":
			resources = append(resources,
				subresource("pods/status", "Pod", true, []string{"get", "patch", "update"}),
				subresource("pods/log", "Pod", true, []string{"get"}),
				subresource("pods/exec", "PodExecOptions", true, []string{"create", "get"}),
				subresource("pods/attach", "PodAttachOptions", true, []string{"create", "get"}),
				subresource("pods/portforward", "PodPortForwardOptions", true, []string{"create", "get"}),
			)
		case "deployments", "statefulsets", "replicasets":
			resources = append(resources,
				subresource(d.name+"/status", d.kind, true, []string{"get", "patch", "update"}),
				subresource(d.name+"/scale", "Scale", true, []string{"get", "patch", "update"}),
			)
		case "services":
			resources = append(resources, subresource("services/proxy", "ServiceProxyOptions", true, []string{"create", "delete", "get", "patch", "update"}))
		}
	}
	gv := version
	if group != "" {
		gv = group + "/" + version
	}
	return map[string]interface{}{
		"kind":         "APIResourceList",
		"apiVersion":   "v1",
		"groupVersion": gv,
		"resources":    resources,
	}
}

func subresource(name, kind string, namespaced bool, verbs []string) map[string]interface{} {
	return map[string]interface{}{
		"name": name, "singularName": "", "namespaced": namespaced, "kind": kind, "verbs": verbs,
	}
}

func apiGroupList() map[string]interface{} {
	groups := make([]interface{}, 0, len(apiGroups))
	for _, g := range apiGroups {
		groups = append(groups, apiGroupObj(g.name, g.versions))
	}
	return map[string]interface{}{
		"kind":       "APIGroupList",
		"apiVersion": "v1",
		"groups":     groups,
	}
}

func apiGroup(name string, versions []string) map[string]interface{} {
	return apiGroupObj(name, versions)
}

func apiGroupObj(name string, versions []string) map[string]interface{} {
	vs := make([]interface{}, 0, len(versions))
	for _, v := range versions {
		vs = append(vs, map[string]interface{}{"groupVersion": name + "/" + v, "version": v})
	}
	preferred := versions[len(versions)-1]
	return map[string]interface{}{
		"kind":       "APIGroup",
		"apiVersion": "v1",
		"name":       name,
		"versions":   vs,
		"preferredVersion": map[string]interface{}{
			"groupVersion": name + "/" + preferred, "version": preferred,
		},
	}
}

func metricsText() string {
	var b strings.Builder
	b.WriteString("# HELP apiserver_request_total Counter of apiserver requests.\n")
	b.WriteString("# TYPE apiserver_request_total counter\n")
	b.WriteString("apiserver_request_total{code=\"200\",verb=\"GET\"} 1234\n")
	b.WriteString("# HELP go_goroutines Number of goroutines that currently exist.\n")
	b.WriteString("# TYPE go_goroutines gauge\n")
	b.WriteString("go_goroutines 42\n")
	return b.String()
}

// ---- 选择器 / 过滤器 ----

func filterItems(items []map[string]interface{}, labelSel, fieldSel string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(items))
	for _, obj := range items {
		if labelSel != "" && !matchLabelSelector(obj, labelSel) {
			continue
		}
		if fieldSel != "" && !matchFieldSelector(obj, fieldSel) {
			continue
		}
		out = append(out, obj)
	}
	return out
}

func matchLabelSelector(obj map[string]interface{}, sel string) bool {
	meta, _ := obj["metadata"].(map[string]interface{})
	labels := map[string]string{}
	if lm, ok := meta["labels"].(map[string]interface{}); ok {
		for k, v := range lm {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
	}
	for _, term := range strings.Split(sel, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if strings.HasPrefix(term, "!") {
			if _, ok := labels[term[1:]]; ok {
				return false
			}
			continue
		}
		if i := strings.Index(term, "!="); i > 0 {
			if labels[term[:i]] == term[i+2:] {
				return false
			}
			continue
		}
		if i := strings.Index(term, "=="); i > 0 {
			if labels[term[:i]] != term[i+2:] {
				return false
			}
			continue
		}
		if i := strings.Index(term, " in "); i > 0 {
			key := strings.TrimSpace(term[:i])
			vals := strings.Trim(strings.TrimSpace(term[i+4:]), "()")
			found := false
			for _, v := range strings.Split(vals, ",") {
				if labels[key] == strings.TrimSpace(v) {
					found = true
				}
			}
			if !found {
				return false
			}
			continue
		}
		if i := strings.Index(term, "="); i > 0 {
			if labels[term[:i]] != term[i+1:] {
				return false
			}
			continue
		}
		// 只给 key：要求存在
		if _, ok := labels[term]; !ok {
			return false
		}
	}
	return true
}

func matchFieldSelector(obj map[string]interface{}, sel string) bool {
	for _, term := range strings.Split(sel, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if i := strings.Index(term, "!="); i > 0 {
			if lookupPath(obj, strings.TrimSpace(term[:i])) == term[i+2:] {
				return false
			}
			continue
		}
		if i := strings.Index(term, "=="); i > 0 {
			if lookupPath(obj, strings.TrimSpace(term[:i])) != term[i+2:] {
				return false
			}
			continue
		}
		if i := strings.Index(term, "="); i > 0 {
			if lookupPath(obj, strings.TrimSpace(term[:i])) != term[i+1:] {
				return false
			}
			continue
		}
	}
	return true
}

// lookupPath 按 a.b.c 取值并转字符串（fieldSelector 用）。
func lookupPath(obj map[string]interface{}, path string) string {
	var cur interface{} = obj
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = m[part]
	}
	switch v := cur.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// applyLimit 实现 limit/continue 分页（continue 是 offset 的 base64）。
func applyLimit(items []map[string]interface{}, limit, cont string) ([]map[string]interface{}, string) {
	n, _ := strconv.Atoi(limit)
	if n <= 0 || len(items) <= n {
		return items, ""
	}
	offset := 0
	if cont != "" {
		if b, err := base64.StdEncoding.DecodeString(cont); err == nil {
			offset, _ = strconv.Atoi(string(b))
		}
	}
	if offset >= len(items) {
		return items[:0], ""
	}
	end := offset + n
	if end > len(items) {
		end = len(items)
	}
	token := ""
	if end < len(items) {
		token = base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	return items[offset:end], token
}

// ---- 服务端表格（kubectl 默认 Accept: application/json;as=Table）----

type tableCol struct {
	name     string
	typ      string
	format   string
	priority int
	desc     string
}

func wantsTable(req *http.Request) bool {
	return strings.Contains(req.Header.Get("Accept"), "as=Table")
}

func buildTable(def resourceDef, items []map[string]interface{}, rv string) map[string]interface{} {
	cols := tableColumns(def)
	colDefs := make([]interface{}, 0, len(cols))
	for _, c := range cols {
		cd := map[string]interface{}{"name": c.name, "type": c.typ, "description": c.desc}
		if c.format != "" {
			cd["format"] = c.format
		}
		if c.priority > 0 {
			cd["priority"] = c.priority
		}
		colDefs = append(colDefs, cd)
	}
	rows := make([]interface{}, 0, len(items))
	for _, obj := range items {
		rows = append(rows, map[string]interface{}{
			"cells":  tableCells(def, obj),
			"object": partialMeta(obj),
		})
	}
	return map[string]interface{}{
		"kind":              "Table",
		"apiVersion":        "meta.k8s.io/v1",
		"metadata":          map[string]interface{}{"resourceVersion": rv},
		"columnDefinitions": colDefs,
		"rows":              rows,
	}
}

func tableColumns(def resourceDef) []tableCol {
	name := tableCol{name: "Name", typ: "string", format: "name", desc: "Name must be unique within a namespace."}
	age := tableCol{name: "Age", typ: "string", desc: "CreationTimestamp is a timestamp representing the server time when this object was created."}
	createdAt := tableCol{name: "Created At", typ: "string", desc: "CreationTimestamp is a timestamp representing the server time when this object was created."}
	wide := func(n string) tableCol { return tableCol{name: n, typ: "string", priority: 1} }
	switch def.name {
	case "pods":
		return []tableCol{name,
			{name: "Ready", typ: "string"},
			{name: "Status", typ: "string"},
			{name: "Restarts", typ: "string"},
			age,
			wide("IP"), wide("Node"), wide("Nominated Node"), wide("Readiness Gates"),
		}
	case "nodes":
		return []tableCol{name,
			{name: "Status", typ: "string"},
			{name: "Roles", typ: "string"},
			age,
			{name: "Version", typ: "string"},
			wide("Internal-IP"), wide("External-IP"), wide("OS-Image"), wide("Kernel-Version"), wide("Container-Runtime"),
		}
	case "namespaces":
		return []tableCol{name, {name: "Status", typ: "string"}, age}
	case "services":
		return []tableCol{name,
			{name: "Type", typ: "string"},
			{name: "Cluster-IP", typ: "string"},
			{name: "External-IP", typ: "string"},
			{name: "Port(s)", typ: "string"},
			age,
			wide("Selector"),
		}
	case "deployments":
		return []tableCol{name,
			{name: "Ready", typ: "string"},
			{name: "Up-to-date", typ: "string"},
			{name: "Available", typ: "string"},
			age,
			wide("Containers"), wide("Images"), wide("Selector"),
		}
	case "replicasets":
		return []tableCol{name,
			{name: "Desired", typ: "string"},
			{name: "Current", typ: "string"},
			{name: "Ready", typ: "string"},
			age,
		}
	case "statefulsets":
		return []tableCol{name, {name: "Ready", typ: "string"}, age}
	case "daemonsets":
		return []tableCol{name,
			{name: "Desired", typ: "string"},
			{name: "Current", typ: "string"},
			{name: "Ready", typ: "string"},
			{name: "Up-to-date", typ: "string"},
			{name: "Available", typ: "string"},
			{name: "Node Selector", typ: "string"},
			age,
		}
	case "configmaps":
		return []tableCol{name, {name: "Data", typ: "string"}, age}
	case "secrets":
		return []tableCol{name, {name: "Type", typ: "string"}, {name: "Data", typ: "string"}, age}
	case "serviceaccounts":
		return []tableCol{name, {name: "Secrets", typ: "string"}, age}
	case "endpoints":
		return []tableCol{name, {name: "Endpoints", typ: "string"}, age}
	case "events":
		return []tableCol{
			{name: "Last Seen", typ: "string"},
			{name: "Type", typ: "string"},
			{name: "Reason", typ: "string"},
			{name: "Object", typ: "string"},
			{name: "Message", typ: "string"},
		}
	case "persistentvolumes":
		return []tableCol{name,
			{name: "Capacity", typ: "string"},
			{name: "Access Modes", typ: "string"},
			{name: "Reclaim Policy", typ: "string"},
			{name: "Status", typ: "string"},
			{name: "Claim", typ: "string"},
			{name: "StorageClass", typ: "string"},
			{name: "VolumeAttributesClass", typ: "string"},
			{name: "Reason", typ: "string"},
			age,
		}
	case "persistentvolumeclaims":
		return []tableCol{name,
			{name: "Status", typ: "string"},
			{name: "Volume", typ: "string"},
			{name: "Capacity", typ: "string"},
			{name: "Access Modes", typ: "string"},
			{name: "StorageClass", typ: "string"},
			{name: "VolumeAttributesClass", typ: "string"},
			age,
		}
	case "jobs":
		return []tableCol{name, {name: "Completions", typ: "string"}, {name: "Duration", typ: "string"}, age}
	case "cronjobs":
		return []tableCol{name,
			{name: "Schedule", typ: "string"},
			{name: "Suspend", typ: "string"},
			{name: "Active", typ: "string"},
			{name: "Last Schedule", typ: "string"},
			age,
		}
	case "ingresses":
		return []tableCol{name,
			{name: "Class", typ: "string"},
			{name: "Hosts", typ: "string"},
			{name: "Address", typ: "string"},
			{name: "Ports", typ: "string"},
			age,
		}
	case "storageclasses":
		return []tableCol{name,
			{name: "Provisioner", typ: "string"},
			{name: "ReclaimPolicy", typ: "string"},
			{name: "VolumeBindingMode", typ: "string"},
			{name: "AllowVolumeExpansion", typ: "string"},
			age,
		}
	case "horizontalpodautoscalers":
		return []tableCol{name,
			{name: "Reference", typ: "string"},
			{name: "Targets", typ: "string"},
			{name: "MinPods", typ: "string"},
			{name: "MaxPods", typ: "string"},
			{name: "Replicas", typ: "string"},
			age,
		}
	case "poddisruptionbudgets":
		return []tableCol{name,
			{name: "Min Available", typ: "string"},
			{name: "Max Unavailable", typ: "string"},
			{name: "Allowed Disruptions", typ: "string"},
			age,
		}
	case "networkpolicies":
		return []tableCol{name, {name: "Pod-Selector", typ: "string"}, age}
	case "leases":
		return []tableCol{name, {name: "Holder", typ: "string"}, age}
	case "roles", "clusterroles", "customresourcedefinitions":
		return []tableCol{name, createdAt}
	}
	return []tableCol{name, age}
}

func tableCells(def resourceDef, obj map[string]interface{}) []interface{} {
	name := mstr(obj, "metadata", "name")
	ageCell := humanAge(mstr(obj, "metadata", "creationTimestamp"))
	switch def.name {
	case "pods":
		ready, status, restarts := podTableStatus(obj)
		return []interface{}{name, ready, status, strconv.Itoa(restarts), ageCell,
			mstr(obj, "status", "podIP"), mstr(obj, "spec", "nodeName"), "<none>", "<none>"}
	case "nodes":
		return []interface{}{name, nodeTableStatus(obj), nodeRoles(obj), ageCell, mstr(obj, "status", "nodeInfo", "kubeletVersion"),
			nodeAddress(obj, "InternalIP"), nodeAddress(obj, "ExternalIP"),
			mstr(obj, "status", "nodeInfo", "osImage"), mstr(obj, "status", "nodeInfo", "kernelVersion"),
			mstr(obj, "status", "nodeInfo", "containerRuntimeVersion")}
	case "namespaces":
		return []interface{}{name, mstr(obj, "status", "phase"), ageCell}
	case "services":
		return []interface{}{name, mstr(obj, "spec", "type"), mstr(obj, "spec", "clusterIP"), "<none>",
			servicePorts(obj), ageCell, selectorString(obj, "spec", "selector")}
	case "deployments":
		replicas := mint(obj, "spec", "replicas")
		return []interface{}{name,
			fmt.Sprintf("%d/%d", mint(obj, "status", "readyReplicas"), replicas),
			strconv.Itoa(mint(obj, "status", "updatedReplicas")),
			strconv.Itoa(mint(obj, "status", "availableReplicas")),
			ageCell,
			containerNames(obj), containerImages(obj), selectorString(obj, "spec", "selector", "matchLabels")}
	case "replicasets":
		return []interface{}{name, strconv.Itoa(mint(obj, "spec", "replicas")), strconv.Itoa(mint(obj, "status", "replicas")),
			strconv.Itoa(mint(obj, "status", "readyReplicas")), ageCell}
	case "statefulsets":
		return []interface{}{name, fmt.Sprintf("%d/%d", mint(obj, "status", "readyReplicas"), mint(obj, "spec", "replicas")), ageCell}
	case "daemonsets":
		return []interface{}{name,
			strconv.Itoa(mint(obj, "status", "desiredNumberScheduled")),
			strconv.Itoa(mint(obj, "status", "currentNumberScheduled")),
			strconv.Itoa(mint(obj, "status", "numberReady")),
			strconv.Itoa(mint(obj, "status", "updatedNumberScheduled")),
			strconv.Itoa(mint(obj, "status", "numberAvailable")),
			selectorString(obj, "spec", "template", "spec", "nodeSelector"), ageCell}
	case "configmaps":
		return []interface{}{name, strconv.Itoa(mapLen(obj, "data")), ageCell}
	case "secrets":
		return []interface{}{name, mstr(obj, "type"), strconv.Itoa(mapLen(obj, "data")), ageCell}
	case "serviceaccounts":
		return []interface{}{name, strconv.Itoa(listLen(obj, "secrets")), ageCell}
	case "endpoints":
		return []interface{}{name, endpointsSummary(obj), ageCell}
	case "events":
		objName := strings.ToLower(mstr(obj, "involvedObject", "kind")) + "/" + mstr(obj, "involvedObject", "name")
		last := humanAge(mstr(obj, "lastTimestamp"))
		return []interface{}{last, mstr(obj, "type"), mstr(obj, "reason"), objName, mstr(obj, "message")}
	case "persistentvolumes":
		return []interface{}{name,
			mstr(obj, "spec", "capacity", "storage"),
			joinList(obj, "spec", "accessModes"),
			mstr(obj, "spec", "persistentVolumeReclaimPolicy"),
			mstr(obj, "status", "phase"),
			claimRef(obj),
			mstr(obj, "spec", "storageClassName"),
			"<unset>", "", ageCell}
	case "persistentvolumeclaims":
		return []interface{}{name,
			mstr(obj, "status", "phase"),
			mstr(obj, "spec", "volumeName"),
			mstr(obj, "status", "capacity", "storage"),
			joinList(obj, "spec", "accessModes"),
			mstr(obj, "spec", "storageClassName"),
			"<unset>", ageCell}
	case "jobs":
		return []interface{}{name, "1/1", "", ageCell}
	case "cronjobs":
		return []interface{}{name, mstr(obj, "spec", "schedule"), "False", "0", "<none>", ageCell}
	case "ingresses":
		hosts := ingressHosts(obj)
		return []interface{}{name, mstr(obj, "spec", "ingressClassName"), hosts, "<none>", "80, 443", ageCell}
	case "storageclasses":
		return []interface{}{name, mstr(obj, "provisioner"), mstr(obj, "reclaimPolicy"), mstr(obj, "volumeBindingMode"),
			fmt.Sprintf("%t", mbool(obj, "allowVolumeExpansion")), ageCell}
	case "horizontalpodautoscalers":
		return []interface{}{name, mstr(obj, "spec", "scaleTargetRef", "kind") + "/" + mstr(obj, "spec", "scaleTargetRef", "name"),
			"<unknown>/50%", strconv.Itoa(mint(obj, "spec", "minReplicas")), strconv.Itoa(mint(obj, "spec", "maxReplicas")),
			strconv.Itoa(mint(obj, "status", "currentReplicas")), ageCell}
	case "poddisruptionbudgets":
		return []interface{}{name, mstr(obj, "spec", "minAvailable"), mstr(obj, "spec", "maxUnavailable"), "1", ageCell}
	case "networkpolicies":
		return []interface{}{name, selectorString(obj, "spec", "podSelector", "matchLabels"), ageCell}
	case "leases":
		return []interface{}{name, mstr(obj, "spec", "holderIdentity"), ageCell}
	case "roles", "clusterroles", "customresourcedefinitions":
		return []interface{}{name, mstr(obj, "metadata", "creationTimestamp")}
	}
	return []interface{}{name, ageCell}
}

// ---- 表格取值辅助 ----

func mget(obj map[string]interface{}, path ...string) interface{} {
	var cur interface{} = obj
	for _, p := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func mstr(obj map[string]interface{}, path ...string) string {
	if s, ok := mget(obj, path...).(string); ok {
		return s
	}
	return ""
}

func mint(obj map[string]interface{}, path ...string) int {
	switch v := mget(obj, path...).(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func mbool(obj map[string]interface{}, path ...string) bool {
	b, _ := mget(obj, path...).(bool)
	return b
}

func mapLen(obj map[string]interface{}, key string) int {
	if m, ok := mget(obj, key).(map[string]interface{}); ok {
		return len(m)
	}
	return 0
}

func listLen(obj map[string]interface{}, key string) int {
	if l, ok := mget(obj, key).([]interface{}); ok {
		return len(l)
	}
	return 0
}

// humanAge 把 creationTimestamp 转成 K8s 风格的 AGE（30s/5m/3h/2d）。
func humanAge(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "<unknown>"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 24*365*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	default:
		return fmt.Sprintf("%dy", int(d.Hours()/24/365))
	}
}

func podTableStatus(pod map[string]interface{}) (ready, status string, restarts int) {
	total := 0
	if cs, ok := mget(pod, "spec", "containers").([]interface{}); ok {
		total = len(cs)
	}
	readyCount := 0
	status = mstr(pod, "status", "phase")
	if cs, ok := mget(pod, "status", "containerStatuses").([]interface{}); ok {
		for _, c := range cs {
			cm, _ := c.(map[string]interface{})
			if b, _ := cm["ready"].(bool); b {
				readyCount++
			}
			restarts += mint(cm, "restartCount")
			if w := mstr(cm, "state", "waiting", "reason"); w != "" {
				status = w
			}
		}
	}
	return fmt.Sprintf("%d/%d", readyCount, total), status, restarts
}

func nodeTableStatus(node map[string]interface{}) string {
	conds, _ := mget(node, "status", "conditions").([]interface{})
	for _, c := range conds {
		cm, _ := c.(map[string]interface{})
		if cm["type"] == "Ready" {
			if cm["status"] == "True" {
				return "Ready"
			}
			return "NotReady"
		}
	}
	return "Unknown"
}

func nodeRoles(node map[string]interface{}) string {
	labels, _ := mget(node, "metadata", "labels").(map[string]interface{})
	roles := make([]string, 0)
	for k := range labels {
		const prefix = "node-role.kubernetes.io/"
		if strings.HasPrefix(k, prefix) {
			roles = append(roles, strings.TrimPrefix(k, prefix))
		}
	}
	if len(roles) == 0 {
		return "<none>"
	}
	sort.Strings(roles)
	return strings.Join(roles, ",")
}

func nodeAddress(node map[string]interface{}, addrType string) string {
	addrs, _ := mget(node, "status", "addresses").([]interface{})
	for _, a := range addrs {
		am, _ := a.(map[string]interface{})
		if am["type"] == addrType {
			if s, ok := am["address"].(string); ok {
				return s
			}
		}
	}
	return "<none>"
}

func servicePorts(svc map[string]interface{}) string {
	ports, _ := mget(svc, "spec", "ports").([]interface{})
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		pm, _ := p.(map[string]interface{})
		proto := "TCP"
		if s, ok := pm["protocol"].(string); ok && s != "" {
			proto = s
		}
		if nodePort := mint(pm, "nodePort"); nodePort > 0 {
			out = append(out, fmt.Sprintf("%d:%d/%s", mint(pm, "port"), nodePort, proto))
		} else {
			out = append(out, fmt.Sprintf("%d/%s", mint(pm, "port"), proto))
		}
	}
	if len(out) == 0 {
		return "<none>"
	}
	return strings.Join(out, ",")
}

func selectorString(obj map[string]interface{}, path ...string) string {
	m, _ := mget(obj, path...).(map[string]interface{})
	if len(m) == 0 {
		return "<none>"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, ",")
}

func containerNames(obj map[string]interface{}) string {
	cs, _ := mget(obj, "spec", "template", "spec", "containers").([]interface{})
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		cm, _ := c.(map[string]interface{})
		if s, ok := cm["name"].(string); ok {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

func containerImages(obj map[string]interface{}) string {
	cs, _ := mget(obj, "spec", "template", "spec", "containers").([]interface{})
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		cm, _ := c.(map[string]interface{})
		if s, ok := cm["image"].(string); ok {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

func endpointsSummary(ep map[string]interface{}) string {
	subsets, _ := mget(ep, "subsets").([]interface{})
	out := make([]string, 0)
	for _, s := range subsets {
		sm, _ := s.(map[string]interface{})
		addrs, _ := sm["addresses"].([]interface{})
		ports, _ := sm["ports"].([]interface{})
		for _, a := range addrs {
			am, _ := a.(map[string]interface{})
			ip, _ := am["ip"].(string)
			for _, p := range ports {
				pm, _ := p.(map[string]interface{})
				out = append(out, fmt.Sprintf("%s:%d", ip, mint(pm, "port")))
			}
		}
	}
	if len(out) == 0 {
		return "<none>"
	}
	return strings.Join(out, ",")
}

func claimRef(obj map[string]interface{}) string {
	ns := mstr(obj, "spec", "claimRef", "namespace")
	name := mstr(obj, "spec", "claimRef", "name")
	if name == "" {
		return "<none>"
	}
	return ns + "/" + name
}

func joinList(obj map[string]interface{}, path ...string) string {
	l, _ := mget(obj, path...).([]interface{})
	out := make([]string, 0, len(l))
	for _, v := range l {
		out = append(out, fmt.Sprintf("%v", v))
	}
	return strings.Join(out, ",")
}

func ingressHosts(ing map[string]interface{}) string {
	rules, _ := mget(ing, "spec", "rules").([]interface{})
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		rm, _ := r.(map[string]interface{})
		if h, ok := rm["host"].(string); ok && h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return "*"
	}
	return strings.Join(out, ",")
}

// partialMeta 表格行的 object 字段（真机为 PartialObjectMetadata）。
func partialMeta(obj map[string]interface{}) map[string]interface{} {
	meta, _ := obj["metadata"].(map[string]interface{})
	out := map[string]interface{}{}
	for _, k := range []string{"name", "namespace", "uid", "resourceVersion", "creationTimestamp"} {
		if v, ok := meta[k]; ok {
			out[k] = v
		}
	}
	return map[string]interface{}{
		"kind":       "PartialObjectMetadata",
		"apiVersion": "meta.k8s.io/v1",
		"metadata":   out,
	}
}

// ---- 对象/补丁辅助 ----

func decodeObject(req *http.Request, body []byte) map[string]interface{} {
	obj := map[string]interface{}{}
	ct := req.Header.Get("Content-Type")
	if strings.Contains(ct, "yaml") {
		if err := yaml.Unmarshal(body, &obj); err != nil || len(obj) == 0 {
			return nil
		}
		return obj
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil
	}
	return obj
}

func objectName(obj map[string]interface{}) string {
	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		if s, ok := meta["name"].(string); ok {
			return s
		}
	}
	return ""
}

func generateName(obj map[string]interface{}) string {
	meta, _ := obj["metadata"].(map[string]interface{})
	if meta == nil {
		return ""
	}
	gen, _ := meta["generateName"].(string)
	if gen == "" {
		return ""
	}
	name := gen + randomSuffix(5)
	meta["name"] = name
	return name
}

func objectRV(obj map[string]interface{}) (string, bool) {
	meta, _ := obj["metadata"].(map[string]interface{})
	if meta == nil {
		return "", false
	}
	s, ok := meta["resourceVersion"].(string)
	return s, ok
}

// initObjectDefaults 给新建对象补真机由控制器/分配器填的默认值：
// Pod 初始 Pending、命名空间 Active、Service 分配 ClusterIP、工作负载补 status 骨架。
func initObjectDefaults(def resourceDef, obj map[string]interface{}) {
	spec, _ := obj["spec"].(map[string]interface{})
	if spec == nil {
		spec = map[string]interface{}{}
	}
	switch def.name {
	case "pods":
		if emptyMap(obj["status"]) {
			obj["status"] = map[string]interface{}{"phase": "Pending", "qosClass": "BestEffort"}
		}
		if _, ok := spec["restartPolicy"]; !ok {
			spec["restartPolicy"] = "Always"
		}
		if _, ok := spec["dnsPolicy"]; !ok {
			spec["dnsPolicy"] = "ClusterFirst"
		}
		if _, ok := spec["schedulerName"]; !ok {
			spec["schedulerName"] = "default-scheduler"
		}
	case "namespaces":
		if emptyMap(obj["status"]) {
			obj["status"] = map[string]interface{}{"phase": "Active"}
		}
	case "services":
		if mstr(obj, "spec", "clusterIP") == "" {
			ip := fmt.Sprintf("10.96.%d.%d", 100+randIndex(100), 1+randIndex(250))
			spec["clusterIP"] = ip
			spec["clusterIPs"] = []interface{}{ip}
		}
		if mstr(obj, "spec", "type") == "" {
			spec["type"] = "ClusterIP"
		}
		if _, ok := spec["sessionAffinity"]; !ok {
			spec["sessionAffinity"] = "None"
		}
		if emptyMap(obj["status"]) {
			obj["status"] = map[string]interface{}{"loadBalancer": map[string]interface{}{}}
		}
	case "deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs":
		if emptyMap(obj["status"]) {
			obj["status"] = map[string]interface{}{}
		}
	}
}

// emptyMap 判断值是否缺失或空对象（kubectl 会把零值 status 序列化成 {}）。
func emptyMap(v interface{}) bool {
	m, ok := v.(map[string]interface{})
	return !ok || len(m) == 0
}

// randIndex 返回 [0,n) 的随机下标。
func randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return int(b[0]) % n
}

// mergePatch 深度合并补丁（null 删除键），数组整体替换。
func mergePatch(dst, patch map[string]interface{}) map[string]interface{} {
	out := deepCopyMap(dst)
	for k, v := range patch {
		if v == nil {
			delete(out, k)
			continue
		}
		if pm, ok := v.(map[string]interface{}); ok {
			if dm, ok := out[k].(map[string]interface{}); ok {
				out[k] = mergePatch(dm, pm)
				continue
			}
			out[k] = deepCopyMap(pm)
			continue
		}
		out[k] = v
	}
	return out
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]interface{}{}
	}
	return out
}

// ---- 响应辅助 ----

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
		data = []byte(`{"kind":"Status","status":"Failure","message":"internal error","code":500}`)
		status = http.StatusInternalServerError
	}
	respond(conn, req, status, "application/json", data)
}

func respondText(conn net.Conn, req *http.Request, status int, text string) {
	respond(conn, req, status, "text/plain; charset=utf-8", []byte(text))
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
	resp.Header.Set("Cache-Control", "no-cache, private")
	resp.Header.Set("Audit-Id", newUUID())
	if req.Method != "HEAD" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := resp.Write(conn); err != nil {
		logger.Log.Debug(serviceName, " write error:", err)
	}
}

// respondStatus K8s 风格 Status 错误 JSON。
func respondStatus(conn net.Conn, req *http.Request, code int, reason, message string, details map[string]interface{}) {
	if details == nil {
		details = map[string]interface{}{}
	}
	respondJSON(conn, req, code, map[string]interface{}{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]interface{}{},
		"status":     "Failure",
		"message":    message,
		"reason":     reason,
		"details":    details,
		"code":       code,
	})
}

// ---- 解析/生成辅助 ----

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func boolQuery(v string) bool {
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// newUUID 生成 UUID v4 形式（K8s metadata.uid 的格式）。
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func randomSuffix(n int) string {
	const alphabet = "bcdfghjklmnpqrstvwxz2456789"
	b := make([]byte, n)
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i := range b {
		b[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(b)
}
