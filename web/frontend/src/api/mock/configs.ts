import type { IConfigFile, IReloadResult, IValidationIssue, IValidationResult } from '../types';
import { PROTOCOL_META } from '@/constants/protocol';
import { formatTimestamp } from './rng';
import { listServices } from './services';
import { mockState } from './state';

const REQUIRED_FIELDS = ['protocol', 'application', 'enable', 'host', 'port'] as const;

/** 与仓库里的真实 yaml 保持同样的风格：中文注释 + 冒号后带引号 */
const RICH_TEMPLATES: Record<string, string> = {
  'docker.yaml': `protocol: "docker-api"
application: "docker-api"
enable: true
host: "0.0.0.0"
# Docker Engine API 默认明文 HTTP 端口 2375（TLS 为 2376）。
# 测试可以使用 export DOCKER_HOST=tcp://127.0.0.1:2375 后使用 docker 命令操作
port: 2375

# ============================================================
# 一、版本指纹（/version 与 /info 联动；留空均取默认值）
# ============================================================
# api_version: "1.45"
# version: "26.1.3"
# min_api_version: "1.24"
# kernel_version: "5.4.0-216-generic"

# ============================================================
# 二、主机身份与资源（/info；建议改成与目标主机一致，避免一眼假）
# ============================================================
# hostname: "docker-host"
# operating_system: "Ubuntu 22.04.3 LTS"
# architecture: "amd64"
# ncpu: 4
# mem_total: 8370600960

# ============================================================
# 三、预置诱饵容器 / 镜像 / 网络 / 卷
# ============================================================
# containers:
#   - name: web
#     image: nginx:latest
#     state: running
#   - name: redis
#     image: redis:7
#     state: running

# ============================================================
# 四、行为调节
# ============================================================
# pull_pace_ms: 250
# idle_timeout_sec: 300
`,
  'ssh.yaml': `protocol: "ssh" #固定字段
application: "ssh"
enable: true
# 监听地址
host: "0.0.0.0"
# 监听端口（SSH 标准 22，此处 2222 避免与宿主 sshd 冲突）
port: 2222

# ssh config
motd: |
  Welcome to Ubuntu 22.04.03 LTS (Jammy Jellyfish)

  * Documentation:  https://help.ubuntu.com
  * Management:     https://landscape.canonical.com

# 最多允许几次认证尝试
max_auth_tries: 3
# 账号口令：配了才校验（用户名+口令完全匹配）；用户名写 "*" 表示通配任意账号。
accounts:
  - username: "root"
    password: "123456"
  - username: "root"
    password: "root"

simulator:
  pwd: /home/user
  ls:  Documents  Downloads  Music  Pictures  Videos
  ps -ef: |
    UID        PID  PPID  C STIME TTY          TIME CMD
    user      1234     1  0 10:00 ?        00:00:00 /usr/lib/systemd/systemd
`,
  'http.yaml': `protocol: "http"
application: "http-phpmyadmin"
enable: true
# 监听地址
host: "0.0.0.0"
# 监听端口
port: 8080

assets_dir: "./services_conf/assets/http/PhpMyAdmin_4.8.1"
index: "home.html"

request_simulator:
  - uri: /download/xx.exe
    method: GET
    response:
      type: file
      #value: "./services_conf/assets/http/xx.exe"
      value: ""  #为空随机生成

  - uri: /test1
    method: GET
    response:
      type: json   # 普通字符串返回
      value: |
        {"code": 0, "msg": "success", "data": "Hello World! test1"}
`,
};

function buildTemplate(file: string, protocol: string, application: string, port: number, enabled: boolean): string {
  const meta = PROTOCOL_META[protocol];
  const groupLine = meta ? `# 协议分类：${meta.group}（显示名 ${meta.label}）` : '# 自定义协议';

  return `protocol: "${protocol}" #固定字段
application: "${application}"
enable: ${enabled}
# 监听地址
host: "0.0.0.0"
# 监听端口
port: ${port}

${groupLine}
# 修改后可在「配置管理」中点「校验」再「生效」，主进程会热加载该实例，
# 无需重启进程，也不会影响其它服务。
#
# 该协议的可选配置项请参考仓库 services_conf/${file} 的注释说明。
`;
}

function seedConfigs(): void {
  for (const service of listServices()) {
    if (mockState.configs.has(service.file)) {
      continue;
    }

    mockState.configs.set(
      service.file,
      RICH_TEMPLATES[service.file] ??
        buildTemplate(service.file, service.protocol, service.application, service.port, service.enabled),
    );
  }
}

export function listConfigFiles(): IConfigFile[] {
  seedConfigs();

  return listServices()
    .map((service) => {
      const content = mockState.configs.get(service.file) ?? '';

      return {
        file: service.file,
        protocol: service.protocol,
        application: service.application,
        path: `services_conf/${service.file}`,
        content,
        dirty: false,
        updatedAt: formatTimestamp(new Date()),
      };
    })
    .sort((a, b) => a.file.localeCompare(b.file));
}

export function getConfig(file: string): IConfigFile {
  const found = listConfigFiles().find((item) => item.file === file);

  if (!found) {
    throw new Error(`配置 ${file} 不存在`);
  }

  return found;
}

/** 提取顶层 key（行首无缩进的 key: value） */
function topLevelFields(content: string): Map<string, string> {
  const fields = new Map<string, string>();

  for (const line of content.split('\n')) {
    const matched = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(line);

    if (matched) {
      fields.set(matched[1], matched[2].replace(/\s+#.*$/, '').trim());
    }
  }

  return fields;
}

function findLine(content: string, field: string): number {
  const lines = content.split('\n');
  const index = lines.findIndex((line) => new RegExp(`^${field}\\s*:`).test(line));

  return index < 0 ? 0 : index + 1;
}

/** 简化版校验：语法（缩进/引号）+ 必填字段 + 端口冲突 */
export function validateConfig(file: string, content: string): IValidationResult {
  const issues: IValidationIssue[] = [];
  const lines = content.split('\n');
  let passed = 0;

  lines.forEach((line, index) => {
    if (line.includes('\t')) {
      issues.push({
        level: 'error',
        line: index + 1,
        field: 'indent',
        message: 'YAML 不允许使用制表符缩进，请改为两个空格',
      });
    }

    const quotes = (line.match(/"/g) ?? []).length;

    if (quotes % 2 !== 0) {
      issues.push({
        level: 'error',
        line: index + 1,
        field: 'syntax',
        message: '双引号未闭合',
      });
    }
  });

  if (issues.length === 0) {
    passed += 1;
  }

  const fields = topLevelFields(content);

  for (const field of REQUIRED_FIELDS) {
    if (!fields.has(field)) {
      issues.push({
        level: 'error',
        line: 0,
        field,
        message: `缺少必填字段 ${field}`,
      });
    } else {
      passed += 1;
    }
  }

  const enableValue = fields.get('enable');

  if (enableValue !== undefined && enableValue !== 'true' && enableValue !== 'false') {
    issues.push({
      level: 'error',
      line: findLine(content, 'enable'),
      field: 'enable',
      message: 'enable 只能是 true 或 false',
    });
  }

  const portValue = Number(fields.get('port'));

  if (fields.has('port') && (!Number.isInteger(portValue) || portValue < 1 || portValue > 65535)) {
    issues.push({
      level: 'error',
      line: findLine(content, 'port'),
      field: 'port',
      message: 'port 必须是 1~65535 之间的整数',
    });
  }

  if (fields.has('port') && Number.isInteger(portValue) && portValue > 0) {
    const conflict = listServices().find((item) => item.file !== file && item.enabled && item.port === portValue);

    if (conflict) {
      issues.push({
        level: 'warning',
        line: findLine(content, 'port'),
        field: 'port',
        message: `端口 ${portValue} 已被 ${conflict.file} 占用，热加载时该实例会启动失败`,
      });
    }
  }

  const protocol = (fields.get('protocol') ?? '').replace(/"/g, '');

  if (protocol && !PROTOCOL_META[protocol]) {
    issues.push({
      level: 'warning',
      line: findLine(content, 'protocol'),
      field: 'protocol',
      message: `协议 ${protocol} 未在当前二进制中注册，实例会被跳过`,
    });
  }

  const hasError = issues.some((issue) => issue.level === 'error');

  return {
    valid: !hasError,
    passed,
    issues,
    checkedAt: formatTimestamp(new Date()),
  };
}

export function saveConfig(file: string, content: string): IConfigFile {
  mockState.configs.set(file, content);

  return { ...getConfig(file), content, dirty: false };
}

export function reloadServices(): IReloadResult {
  const changed = listServices().filter((item) => item.enabled).slice(0, 2);

  return {
    reloaded: changed.length,
    failed: 0,
    durationMs: 240 + changed.length * 60,
    message: `已热加载 ${changed.length} 个实例，未中断已有监听`,
  };
}

export function login(username: string, password: string): { username: string; expiresIn: number } {
  if (username !== 'admin' || password !== 'potagent') {
    throw new Error('用户名或密码不正确');
  }

  return { username, expiresIn: 8 * 3600 };
}
