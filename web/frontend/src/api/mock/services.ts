import type { IServiceItem, IServiceSummary, ServiceStatus } from '../types';
import { createRng, intBetween } from './rng';
import { mockState } from './state';

interface IServiceSeed {
  file: string;
  protocol: string;
  application: string;
  port: number;
  enabled: boolean;
  /** 异常实例：模拟端口被占用导致启动失败 */
  error?: string;
}

/** 与 services_conf/ 下真实 yaml 一一对应（34 个实例，其中 3 个 enable: false） */
const SERVICE_SEEDS: IServiceSeed[] = [
  { file: 'ssh.yaml', protocol: 'ssh', application: 'ssh', port: 2222, enabled: true },
  { file: 'telnet.yaml', protocol: 'telnet', application: 'telnet', port: 23, enabled: true },
  { file: 'rdp.yaml', protocol: 'rdp', application: 'rdp', port: 3389, enabled: true },
  { file: 'vnc.yaml', protocol: 'vnc', application: 'vnc', port: 5901, enabled: true },
  { file: 'http.yaml', protocol: 'http', application: 'http-phpmyadmin', port: 8080, enabled: true },
  { file: 'http_another.yaml', protocol: 'http', application: 'http-wordpress', port: 8081, enabled: true },
  { file: 'https.yaml', protocol: 'https', application: 'https-secure', port: 8443, enabled: true },
  { file: 'docker.yaml', protocol: 'docker-api', application: 'docker-api', port: 2375, enabled: true },
  {
    file: 'kubernetes.yaml',
    protocol: 'kubernetes',
    application: 'kubernetes',
    port: 6443,
    enabled: true,
    error: 'listen tcp4 0.0.0.0:6443: bind: address already in use',
  },
  {
    file: 'elasticsearch.yaml',
    protocol: 'elasticsearch',
    application: 'elasticsearch',
    port: 9200,
    enabled: true,
  },
  { file: 'mysql.yaml', protocol: 'mysql', application: 'mysql', port: 3306, enabled: true },
  { file: 'redis.yaml', protocol: 'redis', application: 'redis', port: 6379, enabled: true },
  { file: 'memcached.yaml', protocol: 'memcached', application: 'memcached', port: 11211, enabled: true },
  { file: 'ldap.yaml', protocol: 'ldap', application: 'ldap', port: 389, enabled: true },
  { file: 'smtp.yaml', protocol: 'smtp', application: 'smtp', port: 25, enabled: true },
  { file: 'smtps.yaml', protocol: 'smtps', application: 'smtps', port: 465, enabled: true },
  { file: 'ftp.yaml', protocol: 'ftp', application: 'ftp', port: 21, enabled: true },
  { file: 'ftps.yaml', protocol: 'ftps', application: 'ftps', port: 990, enabled: true },
  { file: 'tftp.yaml', protocol: 'tftp', application: 'tftp', port: 69, enabled: true },
  { file: 'smb.yaml', protocol: 'smb', application: 'smb', port: 445, enabled: true },
  { file: 'dns.yaml', protocol: 'dns', application: 'dns', port: 53, enabled: false },
  { file: 'ntp.yaml', protocol: 'ntp', application: 'ntp', port: 123, enabled: true },
  { file: 'sntp.yaml', protocol: 'sntp', application: 'sntp', port: 123, enabled: false },
  { file: 'snmp.yaml', protocol: 'snmp', application: 'snmp', port: 161, enabled: true },
  { file: 'sip.yaml', protocol: 'sip', application: 'sip', port: 5060, enabled: true },
  { file: 'modbus.yaml', protocol: 'modbus', application: 'modbus-tcp', port: 502, enabled: true },
  { file: 's7.yaml', protocol: 's7', application: 'siemens-s7', port: 102, enabled: true },
  { file: 'bacnet.yaml', protocol: 'bacnet', application: 'bacnet-ip', port: 47808, enabled: true },
  { file: 'cip.yaml', protocol: 'cip', application: 'allen-bradley-cip', port: 44818, enabled: true },
  { file: 'fins.yaml', protocol: 'fins', application: 'omron-fins', port: 9600, enabled: true },
  {
    file: 'mitsubishi_a1e.yaml',
    protocol: 'mitsubishi_a1e',
    application: 'mitsubishi-a1e',
    port: 8899,
    enabled: true,
  },
  {
    file: 'mitsubishi_qna3e.yaml',
    protocol: 'mitsubishi_qna3e',
    application: 'mitsubishi-qna3e',
    port: 6000,
    enabled: true,
  },
  { file: 'mqtt.yaml', protocol: 'mqtt', application: 'mqtt-broker', port: 1883, enabled: true },
  { file: 'mqtts.yaml', protocol: 'mqtts', application: 'mqtt-broker-tls', port: 8883, enabled: false },
];

/** 热门协议的事件量级，制造真实的"长尾"分布 */
const EVENT_WEIGHT: Record<string, number> = {
  http: 3200,
  https: 1400,
  ssh: 2800,
  redis: 2100,
  'docker-api': 1500,
  mysql: 980,
  telnet: 760,
  rdp: 640,
  elasticsearch: 560,
  kubernetes: 420,
  smb: 380,
  mqtt: 320,
  ftp: 300,
  vnc: 260,
  modbus: 210,
  snmp: 190,
  memcached: 160,
  ldap: 140,
  smtp: 120,
};

function createServices(): IServiceItem[] {
  const rng = createRng(20261023);

  return SERVICE_SEEDS.map((seed) => {
    const status: ServiceStatus = seed.enabled ? (seed.error ? 'error' : 'running') : 'stopped';
    const weight = EVENT_WEIGHT[seed.protocol] ?? intBetween(rng, 20, 120);
    const startedAt =
      status === 'running'
        ? new Date(Date.now() - intBetween(rng, 40, 260) * 60 * 1000).toISOString()
        : null;

    return {
      file: seed.file,
      protocol: seed.protocol,
      application: seed.application,
      host: '0.0.0.0',
      port: seed.port,
      enabled: seed.enabled,
      status,
      connections: status === 'running' ? intBetween(rng, 0, 34) : 0,
      events: weight,
      lastEventAt:
        status === 'running'
          ? new Date(Date.now() - intBetween(rng, 1, 180) * 1000).toISOString()
          : null,
      startedAt,
      lastError: seed.error,
    };
  });
}

function ensureInit(): void {
  if (mockState.services.length === 0) {
    mockState.services = createServices();
  }
}

export function listServices(): IServiceItem[] {
  ensureInit();

  return mockState.services.map((item) => ({ ...item }));
}

export function getServiceSummary(): IServiceSummary {
  ensureInit();

  return mockState.services.reduce<IServiceSummary>(
    (acc, item) => {
      acc.total += 1;

      if (item.status === 'running') {
        acc.running += 1;
      } else if (item.status === 'error') {
        acc.error += 1;
      } else {
        acc.stopped += 1;
      }

      return acc;
    },
    { total: 0, running: 0, stopped: 0, error: 0 },
  );
}

export function findService(file: string): IServiceItem | undefined {
  ensureInit();

  return mockState.services.find((item) => item.file === file);
}

export function setServiceEnabled(file: string, enabled: boolean): IServiceItem {
  const service = findService(file);

  if (!service) {
    throw new Error(`配置 ${file} 不存在`);
  }

  service.enabled = enabled;
  service.status = enabled ? 'running' : 'stopped';
  service.connections = enabled ? Math.max(service.connections, 1) : 0;
  service.startedAt = enabled ? new Date().toISOString() : null;
  service.lastEventAt = enabled ? service.lastEventAt : null;
  service.lastError = undefined;

  return { ...service };
}

export function restartService(file: string): IServiceItem {
  const service = findService(file);

  if (!service) {
    throw new Error(`配置 ${file} 不存在`);
  }

  service.status = service.enabled ? 'running' : 'stopped';
  service.lastError = undefined;
  service.startedAt = service.enabled ? new Date().toISOString() : null;

  return { ...service };
}

/** 日志生成器回调：累加到服务维度与全局维度 */
export function noteEvent(file: string, at: Date): void {
  const service = findService(file);

  if (service) {
    service.events += 1;
    service.lastEventAt = at.toISOString();
  }

  mockState.totalEvents += 1;
  mockState.todayEvents += 1;
}

export function totalConnections(): number {
  ensureInit();

  return mockState.services.reduce((sum, item) => sum + item.connections, 0);
}
