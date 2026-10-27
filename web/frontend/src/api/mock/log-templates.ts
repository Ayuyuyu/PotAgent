import type { IServiceItem } from '../types';
import {
  DOCKER_PATH_POOL,
  HTTP_PATH_POOL,
  HTTP_UA_POOL,
  MYSQL_QUERY_POOL,
  PASSWORD_POOL,
  REDIS_COMMAND_POOL,
  SHELL_COMMAND_POOL,
  USERNAME_POOL,
  pick,
  type Rng,
} from './rng';

/** 各协议最常见的事件类型，命名与 services/ 里 EventPush 的真实取值一致 */
const EVENT_TYPES: Record<string, string[]> = {
  http: ['http-access'],
  https: ['http-access'],
  kubernetes: ['http-access'],
  elasticsearch: ['http-access'],
  ssh: ['ssh-password-authentication', 'ssh-publickey-authentication', 'ssh-shell', 'ssh-exec'],
  telnet: ['telnet-connect', 'telnet-login'],
  rdp: ['rdp-connect', 'rdp-negotiate'],
  vnc: ['vnc-connect', 'vnc-handshake'],
  'docker-api': ['docker-request', 'docker-connect'],
  mysql: ['mysql-connect', 'mysql-command'],
  redis: ['redis-command', 'redis-connect'],
  memcached: ['memcached-command', 'memcached-connect'],
  ldap: ['ldap-bind', 'ldap-search'],
  ftp: ['ftp-command', 'ftp-login'],
  ftps: ['ftp-command', 'ftp-login'],
  smtp: ['smtp-command', 'smtp-mail'],
  smtps: ['smtps-command', 'smtps-mail'],
  dns: ['dns-query'],
  ntp: ['ntp-request'],
  sntp: ['sntp-request'],
  snmp: ['snmp-request'],
  sip: ['sip-request'],
  modbus: ['modbus-request'],
  s7: ['s7-request'],
  bacnet: ['bacnet-request'],
  cip: ['cip-request'],
  fins: ['fins-request'],
  mitsubishi_a1e: ['mitsubishi-a1e-request'],
  mitsubishi_qna3e: ['mitsubishi-qna3e-request'],
  mqtt: ['mqtt-connect', 'mqtt-publish'],
  mqtts: ['mqtts-connect', 'mqtts-publish'],
  tftp: ['tftp-request'],
  smb: ['smb-negotiate'],
};

export function buildEventType(rng: Rng, protocol: string): string {
  const pool = EVENT_TYPES[protocol] ?? [`${protocol}-request`];

  return pick(rng, pool);
}

function buildHttpDetails(rng: Rng, service: IServiceItem): Record<string, unknown> {
  const method = rng() > 0.72 ? 'POST' : 'GET';
  const path = pick(rng, HTTP_PATH_POOL);

  return {
    protocol: service.protocol,
    application: service.application,
    'http.method': method,
    'http.host': `${service.host === '0.0.0.0' ? '10.0.3.17' : service.host}:${service.port}`,
    'http.url': path,
    'http.request_headers': {
      'User-Agent': pick(rng, HTTP_UA_POOL),
      Accept: '*/*',
      Connection: 'close',
    },
    'http.request_body': method === 'POST' ? 'username=admin&password=admin123' : '',
  };
}

/** 按协议生成 details，字段名取自各服务 EventPush 实际写入的键 */
export function buildDetails(rng: Rng, service: IServiceItem): Record<string, unknown> {
  const protocol = service.protocol;
  const base = { protocol, application: service.application };

  switch (protocol) {
    case 'http':
    case 'https':
    case 'kubernetes':
    case 'elasticsearch':
      return buildHttpDetails(rng, service);

    case 'ssh':
      return {
        ...base,
        'ssh.username': pick(rng, USERNAME_POOL),
        'ssh.password': pick(rng, PASSWORD_POOL),
        'ssh.session-id': `c${Math.floor(rng() * 1e9).toString(36)}`,
        ...(rng() > 0.85 ? { 'ssh.shell': pick(rng, SHELL_COMMAND_POOL) } : {}),
      };

    case 'telnet':
      return {
        ...base,
        'telnet.username': pick(rng, USERNAME_POOL),
        'telnet.password': pick(rng, PASSWORD_POOL),
        'telnet.session-id': `c${Math.floor(rng() * 1e9).toString(36)}`,
      };

    case 'rdp':
      return {
        ...base,
        'rdp.username': pick(rng, USERNAME_POOL),
        'rdp.cookie': `mstshash=${pick(rng, USERNAME_POOL)}`,
        'rdp.session-id': Math.floor(rng() * 1e6),
      };

    case 'vnc':
      return {
        ...base,
        'vnc.version': 'RFB 003.008',
        'vnc.security-type': pick(rng, [1, 2, 16, 18]),
      };

    case 'docker-api':
      return {
        ...base,
        'docker.method': rng() > 0.8 ? 'POST' : 'GET',
        'docker.path': pick(rng, DOCKER_PATH_POOL),
        'docker.user_agent': pick(rng, ['docker/26.1.3 go/go1.22.2', 'curl/8.5.0', 'Go-http-client/1.1']),
        'docker.session-id': `c${Math.floor(rng() * 1e9).toString(36)}`,
        ...(rng() > 0.9 ? { 'docker.authorization': 'Basic cm9vdDpob25leXBvdA==' } : {}),
      };

    case 'mysql':
      return {
        ...base,
        'mysql.username': pick(rng, USERNAME_POOL),
        'mysql.auth_plugin': 'mysql_native_password',
        'mysql.client_name': pick(rng, ['mysql', 'navicat', 'libmysql']),
        'mysql.query': pick(rng, MYSQL_QUERY_POOL),
      };

    case 'redis':
      return {
        ...base,
        'redis.session-id': `c${Math.floor(rng() * 1e9).toString(36)}`,
        'redis.command': pick(rng, REDIS_COMMAND_POOL),
      };

    case 'memcached':
      return {
        ...base,
        'memcached.command': pick(rng, ['get', 'set', 'stats', 'version', 'flush_all']),
        'memcached.key': pick(rng, ['session:0f2a', 'cache:home', 'user:admin', 'flag']),
      };

    case 'ldap':
      return {
        ...base,
        'ldap.op': pick(rng, ['bindRequest', 'searchRequest']),
        'ldap.dn': `cn=${pick(rng, USERNAME_POOL)},dc=example,dc=com`,
        'ldap.password': pick(rng, PASSWORD_POOL),
      };

    case 'ftp':
    case 'ftps':
      return {
        ...base,
        'ftp.command': pick(rng, ['USER root', 'PASS 123456', 'LIST', 'RETR /etc/passwd', 'STOR shell.php']),
        'ftp.username': pick(rng, USERNAME_POOL),
      };

    case 'smtp':
    case 'smtps':
      return {
        ...base,
        'smtp.command': pick(rng, ['EHLO scan.local', 'AUTH LOGIN', 'MAIL FROM:<root@scan.local>', 'RCPT TO:<admin@corp.local>']),
        'smtp.username': pick(rng, USERNAME_POOL),
        'smtp.password': pick(rng, PASSWORD_POOL),
      };

    case 'dns':
      return {
        ...base,
        'dns.query-id': Math.floor(rng() * 65535),
        'dns.question': pick(rng, ['version.bind', 'localhost', 'www.baidu.com', 'isc.org']),
        'ip_protocol': 'udp',
      };

    case 'ntp':
    case 'sntp':
      return {
        ...base,
        'ntp.version': pick(rng, [3, 4]),
        'ip_protocol': 'udp',
      };

    case 'snmp':
      return {
        ...base,
        'snmp.version': pick(rng, ['v1', 'v2c']),
        'snmp.community': pick(rng, ['public', 'private', 'cisco']),
        'snmp.pdu_type': pick(rng, ['GetRequest', 'GetBulkRequest', 'SetRequest']),
        'ip_protocol': 'udp',
      };

    case 'sip':
      return {
        ...base,
        'sip.method': pick(rng, ['REGISTER', 'INVITE', 'OPTIONS']),
        'sip.uri': `sip:${1000 + Math.floor(rng() * 8000)}@10.0.3.17`,
        'sip.from_user': String(1000 + Math.floor(rng() * 8000)),
        'sip.user_agent': pick(rng, ['friendly-scanner', 'sipvicious', 'pplsip']),
      };

    case 'modbus':
      return {
        ...base,
        'modbus.function': pick(rng, [1, 3, 4, 6, 16, 43]),
        'modbus.address': Math.floor(rng() * 1000),
        'modbus.quantity': pick(rng, [1, 2, 10, 125]),
        'modbus.unit-id': 1,
      };

    case 's7':
      return { ...base, 's7.items': 'DB1.DBD0', 's7.stored': rng() > 0.5 };

    case 'bacnet':
      return {
        ...base,
        'bacnet.service': pick(rng, ['readProperty', 'writeProperty', 'whoIs']),
        'bacnet.instance': Math.floor(rng() * 4194303),
        'bacnet.property': 'present-value',
      };

    case 'cip':
      return {
        ...base,
        'cip.address': `0x${Math.floor(rng() * 65535).toString(16)}`,
        'cip.value': Math.floor(rng() * 255),
      };

    case 'fins':
      return {
        ...base,
        'fins.command': pick(rng, ['0101', '0102', '0201']),
        'fins.address': `D${Math.floor(rng() * 5000)}`,
      };

    case 'mitsubishi_a1e':
    case 'mitsubishi_qna3e':
      return {
        ...base,
        'mitsubishi.command': pick(rng, ['0401', '0406', '1401']),
        'mitsubishi.address': `D${Math.floor(rng() * 3000)}`,
      };

    case 'mqtt':
    case 'mqtts':
      return {
        ...base,
        'mqtt.packet-type': pick(rng, ['CONNECT', 'SUBSCRIBE', 'PUBLISH']),
        'mqtt.client-id': `mqtt_${Math.floor(rng() * 1e6).toString(36)}`,
        'mqtt.username': pick(rng, USERNAME_POOL),
        'mqtt.password': pick(rng, PASSWORD_POOL),
        'mqtt.topic': pick(rng, ['/sensors/temp', 'factory/line1/state', '$SYS/#']),
      };

    case 'tftp':
      return {
        ...base,
        'tftp.operation': pick(rng, ['RRQ', 'WRQ']),
        'tftp.filename': pick(rng, ['config.bin', 'firmware.img', 'startup-config']),
        'tftp.mode': 'octet',
        'ip_protocol': 'udp',
      };

    case 'smb':
      return {
        ...base,
        'smb.version': pick(rng, ['SMB1', 'SMB2', 'SMB3']),
        'smb.raw-head': 'ff534d72',
      };

    default:
      return { ...base };
  }
}
