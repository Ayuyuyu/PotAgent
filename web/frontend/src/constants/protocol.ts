/** 协议徽标色调，对应 Tailwind 语义色 */
export type ProtocolTone = 'primary' | 'info' | 'success' | 'warning' | 'danger' | 'accent';

export interface IProtocolMeta {
  key: string;
  label: string;
  group: ProtocolGroup;
  tone: ProtocolTone;
}

export type ProtocolGroup =
  | '远程登录'
  | 'Web 服务'
  | '容器编排'
  | '数据库与缓存'
  | '邮件服务'
  | '文件传输'
  | '网络服务'
  | '工控协议';

/** 与 services/ 下各包 services.Register 的 key 严格一致 */
export const PROTOCOL_META: Record<string, IProtocolMeta> = {
  ssh: { key: 'ssh', label: 'SSH', group: '远程登录', tone: 'primary' },
  telnet: { key: 'telnet', label: 'Telnet', group: '远程登录', tone: 'primary' },
  rdp: { key: 'rdp', label: 'RDP', group: '远程登录', tone: 'primary' },
  vnc: { key: 'vnc', label: 'VNC', group: '远程登录', tone: 'primary' },

  http: { key: 'http', label: 'HTTP', group: 'Web 服务', tone: 'info' },
  https: { key: 'https', label: 'HTTPS', group: 'Web 服务', tone: 'info' },
  'docker-api': { key: 'docker-api', label: 'Docker API', group: '容器编排', tone: 'info' },
  kubernetes: { key: 'kubernetes', label: 'Kubernetes', group: '容器编排', tone: 'info' },

  // Redis/Memcached 是缓存，LDAP 是目录型数据库，Elasticsearch 是搜索型存储，统一归到这一组
  elasticsearch: { key: 'elasticsearch', label: 'Elasticsearch', group: '数据库与缓存', tone: 'accent' },
  mysql: { key: 'mysql', label: 'MySQL', group: '数据库与缓存', tone: 'accent' },
  redis: { key: 'redis', label: 'Redis', group: '数据库与缓存', tone: 'accent' },
  memcached: { key: 'memcached', label: 'Memcached', group: '数据库与缓存', tone: 'accent' },
  ldap: { key: 'ldap', label: 'LDAP', group: '数据库与缓存', tone: 'accent' },

  smtp: { key: 'smtp', label: 'SMTP', group: '邮件服务', tone: 'warning' },
  smtps: { key: 'smtps', label: 'SMTPS', group: '邮件服务', tone: 'warning' },

  ftp: { key: 'ftp', label: 'FTP', group: '文件传输', tone: 'success' },
  ftps: { key: 'ftps', label: 'FTPS', group: '文件传输', tone: 'success' },
  tftp: { key: 'tftp', label: 'TFTP', group: '文件传输', tone: 'success' },
  smb: { key: 'smb', label: 'SMB', group: '文件传输', tone: 'success' },

  dns: { key: 'dns', label: 'DNS', group: '网络服务', tone: 'danger' },
  ntp: { key: 'ntp', label: 'NTP', group: '网络服务', tone: 'danger' },
  sntp: { key: 'sntp', label: 'SNTP', group: '网络服务', tone: 'danger' },
  snmp: { key: 'snmp', label: 'SNMP', group: '网络服务', tone: 'danger' },
  sip: { key: 'sip', label: 'SIP', group: '网络服务', tone: 'danger' },

  bacnet: { key: 'bacnet', label: 'BACnet', group: '工控协议', tone: 'warning' },
  cip: { key: 'cip', label: 'EtherNet/IP', group: '工控协议', tone: 'warning' },
  fins: { key: 'fins', label: 'OMRON FINS', group: '工控协议', tone: 'warning' },
  mitsubishi_a1e: { key: 'mitsubishi_a1e', label: 'MELSEC A-1E', group: '工控协议', tone: 'warning' },
  mitsubishi_qna3e: { key: 'mitsubishi_qna3e', label: 'MELSEC QnA3E', group: '工控协议', tone: 'warning' },
  modbus: { key: 'modbus', label: 'Modbus TCP', group: '工控协议', tone: 'warning' },
  mqtt: { key: 'mqtt', label: 'MQTT', group: '工控协议', tone: 'warning' },
  mqtts: { key: 'mqtts', label: 'MQTTS', group: '工控协议', tone: 'warning' },
  s7: { key: 's7', label: 'Siemens S7', group: '工控协议', tone: 'warning' },
};

export const PROTOCOL_GROUPS: ProtocolGroup[] = [
  '远程登录',
  'Web 服务',
  '容器编排',
  '数据库与缓存',
  '邮件服务',
  '文件传输',
  '网络服务',
  '工控协议',
];

const FALLBACK_META: IProtocolMeta = {
  key: 'unknown',
  label: '未知协议',
  group: '网络服务',
  tone: 'info',
};

export function getProtocolMeta(key: string, fallbackLabel?: string): IProtocolMeta {
  const meta = PROTOCOL_META[key];

  if (meta) {
    return meta;
  }

  return { ...FALLBACK_META, key, label: fallbackLabel ?? key.toUpperCase() };
}
