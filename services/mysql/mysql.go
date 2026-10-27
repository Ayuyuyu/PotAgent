package mysql

/*
MySQL 蜜罐服务（TCP 3306，MySQL 客户端/服务端协议，MySQL 5.7/8.0 线格式）。

低交互策略：
  - 连接后立即发 Initial Handshake Packet（protocol 10）：带服务端版本、线程 id、
    20 字节随机 salt、能力位与 auth_plugin_name=mysql_native_password。
    能力位里刻意不含 CLIENT_SSL（无 TLS 实现，客户端会自动回落明文），
    也不含 CLIENT_DEPRECATE_EOF（用经典 EOF 包，实现更简单）。
  - 读 Handshake Response，提取 username、auth_response（mysql_native_password 的
     challenge-response）、database、auth_plugin 与客户端属性（_os/_client_name/
    _client_version 等）。**不校验口令，一律回 OK 放行**（与 ftp/smtp/redis/ldap/
    mqtt 一致），于是攻击者会继续发 SQL，查询内容成为核心情报。
    事件里同时落 salt：auth_response 只有配合 salt 才能离线破解（hashcat -m 300）。
  - 命令循环处理 COM_QUIT / COM_PING / COM_INIT_DB / COM_QUERY / COM_FIELD_LIST /
    COM_STMT_PREPARE / COM_STMT_EXECUTE / COM_RESET_CONNECTION / COM_SET_OPTION。
  - COM_QUERY 的响应按 SQL 语义伪造：SELECT VERSION()/USER()/DATABASE()/@@xxx、
    SHOW DATABASES/TABLES/VARIABLES/STATUS/GRANTS、information_schema 等常见探测
    返回像真的结果集，其余 SELECT 返回单列空结果集，写操作回 OK。
    LOAD DATA LOCAL INFILE / INTO OUTFILE 一类外传意图完整落事件（不实现）。
  - 未实现：caching_sha2_password（MySQL 8 默认插件）、压缩协议、多语句的
    逐条结果集（只回一条）。客户端若强挑这些能力会拿到 ERR 或空响应。
  - 事件 mysql-connect / mysql-login / mysql-command / mysql-close；
    mysql-login 含 username/auth_response/salt/database/auth_plugin/客户端属性，
    mysql-command 含 command/query/db，均带 session-id(xid) 与 thread-id。
*/

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"github.com/rs/xid"
)

const (
	defaultVersion = "5.7.42-log"
	defaultPlugin  = "mysql_native_password"

	// maxPacketLen 单包 payload 上限（MySQL 协议头 3 字节，最大 0xFFFFFF）。
	maxPacketLen = 1<<24 - 1
	// connIdleTimeout 命令循环空闲多久后断开。
	connIdleTimeout = 300 * time.Second
)

// ---- 协议常量 ----

const (
	// 客户端能力位（服务端在握手包里通告的子集）
	capLongPassword     = 0x00000001
	capFoundRows        = 0x00000002
	capLongFlag         = 0x00000004
	capConnectWithDB    = 0x00000008
	capProtocol41       = 0x00000200
	capTransactions     = 0x00002000
	capSecureConnection = 0x00008000
	capMultiStatements  = 0x00010000
	capMultiResults     = 0x00020000
	capPluginAuth       = 0x00080000
	capConnectAttrs     = 0x00100000
	capPluginAuthLenenc = 0x00200000

	// 命令字节
	comQuit             = 0x01
	comInitDB           = 0x02
	comQuery            = 0x03
	comFieldList        = 0x04
	comPing             = 0x0e
	comStatistics       = 0x09
	comProcessInfo      = 0x0a
	comDebug            = 0x0d
	comChangeUser       = 0x11
	comStmtPrepare      = 0x16
	comStmtExecute      = 0x17
	comStmtSendLongData = 0x18
	comStmtClose        = 0x19
	comStmtReset        = 0x1a
	comSetOption        = 0x1b
	comStmtFetch        = 0x1c
	comResetConnection  = 0x1f

	// 字段类型（文本结果统一用 MYSQL_TYPE_VAR_STRING）
	typeVarString = 0xfd
	typeLongLong  = 0x08
	typeDouble    = 0x05

	// 服务端状态
	statusAutocommit = 0x0002
)

// serverCapabilities 服务端通告的能力位。
var serverCapabilities = uint32(capLongPassword | capFoundRows | capLongFlag |
	capConnectWithDB | capProtocol41 | capTransactions | capSecureConnection |
	capMultiStatements | capMultiResults | capPluginAuth | capConnectAttrs |
	capPluginAuthLenenc)

var (
	serviceName = "mysql"
	_           = services.Register(serviceName, MySQLServiceInit)
)

func MySQLServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   mysqlHandle,
		ServiceOptions: mysqlConfig{},
	}
}

// mysqlConfig 协议专属配置。各项留空均回退内置默认值；
// 带「版本相关」标注的项会按 version 的大版本/发行风味自动推导。
type mysqlConfig struct {
	Version    string   `mapstructure:"version"`
	AuthPlugin string   `mapstructure:"auth_plugin"`
	Databases  []string `mapstructure:"databases"`
	Tables     []string `mapstructure:"tables"`

	// 以下为部署/版本指纹细节。留空则按 version 推导或取内置默认，
	// 只有要精确伪装某个特定发行版/部署时才需要显式配置。
	VersionComment string `mapstructure:"version_comment"` // 版本相关：MariaDB/Percona/官方 MySQL 各不相同
	Hostname       string `mapstructure:"hostname"`
	DataDir        string `mapstructure:"datadir"`
	BaseDir        string `mapstructure:"basedir"`
	Socket         string `mapstructure:"socket"`
	SQLMode        string `mapstructure:"sql_mode"` // 版本相关：5.6/5.7/8.0 默认值不同
	HaveSSL        string `mapstructure:"have_ssl"` //
	MaxConnections string `mapstructure:"max_connections"`
}

func (c mysqlConfig) version() string {
	if c.Version != "" {
		return c.Version
	}
	return defaultVersion
}

// majorVersion 取 version 的大版本号（解析不了返回 0）。
func (c mysqlConfig) majorVersion() int {
	n, _ := strconv.Atoi(strings.SplitN(strings.TrimSpace(c.version()), ".", 2)[0])
	return n
}

// mysqlFlavor 发行风味。同一个 3306 端口上 MySQL / MariaDB / Percona 的默认
// 行为（默认认证插件、默认 sql_mode 等）并不相同，单看大版本号分不清，需要
// 先按 version 串判别风味再决定默认值。
type mysqlFlavor int

const (
	flavorMySQL mysqlFlavor = iota
	flavorMariaDB
	flavorPercona
)

func (c mysqlConfig) flavor() mysqlFlavor {
	switch v := strings.ToLower(c.version()); {
	case strings.Contains(v, "mariadb"):
		return flavorMariaDB
	case strings.Contains(v, "percona"):
		return flavorPercona
	default:
		return flavorMySQL
	}
}

func (c mysqlConfig) authPlugin() string {
	if c.AuthPlugin != "" {
		return c.AuthPlugin
	}
	// MariaDB 10.x 即便大版本号 ≥ 8，默认仍是 mysql_native_password（不是
	// caching_sha2_password），所以先按风味判断。
	if c.flavor() == flavorMariaDB {
		return defaultPlugin
	}
	// MySQL 8.0 起默认 caching_sha2_password（5.7 及更早是 mysql_native_password）。
	// 这里不做完整协商：通告插件后照常记录客户端响应并一律回 OK 放行，
	// 所以想要严格对应版本就把这项显式配成版本对应的插件名。
	if c.majorVersion() >= 8 {
		return "caching_sha2_password"
	}
	return defaultPlugin
}

// versionComment 按 version 串猜发行风味（版本相关，且是最强的 flavor 指纹）。
func (c mysqlConfig) versionComment() string {
	if c.VersionComment != "" {
		return c.VersionComment
	}
	switch v := strings.ToLower(c.version()); {
	case strings.Contains(v, "mariadb"):
		return "MariaDB"
	case strings.Contains(v, "percona"):
		return "Percona Server (GPL)"
	default:
		return "MySQL Community Server - GPL"
	}
}

// sqlMode 按风味 + 大版本给默认值（MariaDB 与 MySQL 的默认 sql_mode 不同）。
func (c mysqlConfig) sqlMode() string {
	if c.SQLMode != "" {
		return c.SQLMode
	}
	// MariaDB 10.2.4+ 默认 sql_mode 比 MySQL 8.0 简单（没有 ONLY_FULL_GROUP_BY）。
	if c.flavor() == flavorMariaDB {
		return "STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
	}
	switch {
	case c.majorVersion() >= 8:
		return "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"
	case c.majorVersion() == 7:
		return "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
	default:
		return "NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES"
	}
}

func (c mysqlConfig) hostname() string {
	if c.Hostname != "" {
		return c.Hostname
	}
	return "mysql-master"
}

func (c mysqlConfig) dataDir() string {
	if c.DataDir != "" {
		return c.DataDir
	}
	return "/var/lib/mysql/"
}

func (c mysqlConfig) baseDir() string {
	if c.BaseDir != "" {
		return c.BaseDir
	}
	return "/usr/"
}

func (c mysqlConfig) socket() string {
	if c.Socket != "" {
		return c.Socket
	}
	return "/var/run/mysqld/mysqld.sock"
}

func (c mysqlConfig) haveSSL() string {
	if c.HaveSSL != "" {
		return c.HaveSSL
	}
	return "YES"
}

func (c mysqlConfig) maxConnections() string {
	if c.MaxConnections != "" {
		return c.MaxConnections
	}
	return "151"
}

func (c mysqlConfig) databases() []string {
	if len(c.Databases) > 0 {
		return c.Databases
	}
	return []string{"information_schema", "mysql", "performance_schema", "test"}
}

func (c mysqlConfig) tables() []string {
	if len(c.Tables) > 0 {
		return c.Tables
	}
	return []string{"users", "accounts", "orders", "sessions"}
}

// ---- 连接处理 ----

func mysqlHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Errorln(err)
		service.ReportError(err)
		return
	}
	defer listen.Close()
	logger.Log.Infof("%s listen on %s", baseOptions.Application, address)

	service.MarkReady()

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleConn(conn, service)
		}
	}
}

func handleConn(conn net.Conn, service *services.Service) {
	defer conn.Close()
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(mysqlConfig)

	id := xid.New()
	threadID := binary.BigEndian.Uint32(randomBytes(4))
	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}

	push := func(eventType string, details map[string]interface{}) {
		details["protocol"] = baseOptions.Protocol
		details["application"] = baseOptions.Application
		details["mysql.session-id"] = id.String()
		details["mysql.thread-id"] = threadID
		event.EventPush(event.NewEvent(serviceName, eventType, srcAddr, dstAddr, details))
	}

	c := &mysqlConn{conn: conn, br: bufio.NewReader(conn)}
	s := &mysqlSession{cfg: cfg, port: baseOptions.Port, db: "", user: "", push: push}

	// 1) 服务端握手
	salt := randomBytes(20)
	if err := c.writePacket(buildGreeting(cfg, threadID, salt)); err != nil {
		logger.Log.Debug(serviceName, " write greeting:", err)
		return
	}

	// 2) 客户端握手响应 -> 抓凭证
	resp, err := c.readPacket()
	if err != nil || len(resp) == 0 {
		return
	}
	login, perr := parseHandshakeResponse(resp)
	if perr != nil {
		// 响应不合协议：回 ERR 后断开
		_ = c.writePacket(buildErrPacket(1045, "28000", "Access denied"))
		return
	}
	s.user = login.username
	s.db = login.database
	push("mysql-login", map[string]interface{}{
		"mysql.username":       login.username,
		"mysql.database":       login.database,
		"mysql.auth_plugin":    login.authPlugin,
		"mysql.auth_response":  hex.EncodeToString(login.authResponse),
		"mysql.salt":           hex.EncodeToString(salt),
		"mysql.client_attrs":   login.attrs,
		"mysql.client_os":      login.attrs["_os"],
		"mysql.client_name":    login.attrs["_client_name"],
		"mysql.client_version": login.attrs["_client_version"],
		"mysql.max_packet":     login.maxPacket,
		"mysql.charset":        login.charset,
	})

	push("mysql-connect", map[string]interface{}{
		"mysql.username": login.username,
		"mysql.database": login.database,
	})

	// 3) 认证结果：不校验，一律放行
	if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
		return
	}

	// 4) 命令循环
	_ = conn.SetReadDeadline(time.Now().Add(connIdleTimeout))
	for {
		payload, err := c.readPacket()
		if err != nil {
			break
		}
		if len(payload) == 0 {
			continue
		}
		cmd := payload[0]
		_ = conn.SetReadDeadline(time.Now().Add(connIdleTimeout))

		switch cmd {
		case comQuit:
			push("mysql-close", map[string]interface{}{})
			return
		case comPing:
			if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		case comInitDB:
			if len(payload) > 1 {
				s.db = string(payload[1:])
			}
			if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		case comQuery:
			sql := string(payload[1:])
			push("mysql-command", map[string]interface{}{
				"mysql.command": "COM_QUERY",
				"mysql.query":   sql,
				"mysql.db":      s.db,
			})
			rs, isResult := s.answer(sql)
			if isResult {
				if err := c.writeResultSet(rs); err != nil {
					return
				}
			} else if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		case comFieldList:
			// COM_FIELD_LIST <table>\0 只回 EOF（空字段列表）
			if err := c.writePacket(buildEOFPacket(statusAutocommit)); err != nil {
				return
			}
		case comStmtPrepare:
			push("mysql-command", map[string]interface{}{
				"mysql.command": "COM_STMT_PREPARE",
				"mysql.query":   string(payload[1:]),
				"mysql.db":      s.db,
			})
			if err := c.writePacket(buildStmtPrepareOK()); err != nil {
				return
			}
		case comStmtExecute, comStmtSendLongData, comStmtClose, comStmtReset, comStmtFetch:
			// 预处理语句族：只记录不真正执行（payload 里的占位参数一并落事件）
			push("mysql-command", map[string]interface{}{
				"mysql.command": comName(cmd),
				"mysql.raw":     hex.EncodeToString(payload[1:]),
				"mysql.db":      s.db,
			})
			if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		case comResetConnection:
			s.db = ""
			if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		case comSetOption:
			if err := c.writePacket(buildEOFPacket(statusAutocommit)); err != nil {
				return
			}
		case comChangeUser:
			// 重新认证：按新请求再抓一次凭证
			if l, e := parseHandshakeResponse(payload[1:]); e == nil {
				s.user, s.db = l.username, l.database
				push("mysql-login", map[string]interface{}{
					"mysql.username":      l.username,
					"mysql.database":      l.database,
					"mysql.auth_plugin":   l.authPlugin,
					"mysql.auth_response": hex.EncodeToString(l.authResponse),
					"mysql.salt":          hex.EncodeToString(salt),
					"mysql.client_attrs":  l.attrs,
					"mysql.reauth":        true,
				})
			}
			if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		case comStatistics, comProcessInfo, comDebug:
			if err := c.writePacket(buildOKPacket(0, 0, statusAutocommit)); err != nil {
				return
			}
		default:
			push("mysql-command", map[string]interface{}{
				"mysql.command": comName(cmd),
				"mysql.raw":     hex.EncodeToString(payload[1:]),
				"mysql.db":      s.db,
			})
			// 未知命令按 ERR 应答，避免客户端挂住
			if err := c.writePacket(buildErrPacket(1047, "08S01", "Unknown command")); err != nil {
				return
			}
		}
	}
	push("mysql-close", map[string]interface{}{})
}

func comName(cmd byte) string {
	names := map[byte]string{
		comQuit: "COM_QUIT", comInitDB: "COM_INIT_DB", comQuery: "COM_QUERY",
		comFieldList: "COM_FIELD_LIST", comPing: "COM_PING", comStatistics: "COM_STATISTICS",
		comProcessInfo: "COM_PROCESS_INFO", comDebug: "COM_DEBUG",
		comChangeUser: "COM_CHANGE_USER", comStmtPrepare: "COM_STMT_PREPARE",
		comStmtExecute: "COM_STMT_EXECUTE", comStmtClose: "COM_STMT_CLOSE",
		comStmtReset: "COM_STMT_RESET", comSetOption: "COM_SET_OPTION",
		comResetConnection: "COM_RESET_CONNECTION",
	}
	if n, ok := names[cmd]; ok {
		return n
	}
	return fmt.Sprintf("COM_0x%02x", cmd)
}

// mysqlSession 保存一次连接的会话状态。
type mysqlSession struct {
	cfg  mysqlConfig
	port uint16 // 实际监听端口，用于 @@port（改端口时响应要跟着变）
	db   string
	user string
	push func(string, map[string]interface{})
}

// ---- 包读写 ----

// mysqlConn 维护包序号：每写一包自增，读包后重置为对端序号+1（MySQL 语义）。
type mysqlConn struct {
	conn net.Conn
	br   *bufio.Reader
	seq  byte
}

// readPacket 读一个完整包（含多包拼接）。
func (c *mysqlConn) readPacket() ([]byte, error) {
	var out []byte
	for {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(c.br, hdr); err != nil {
			return nil, err
		}
		length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		c.seq = hdr[3] + 1
		if length > 0 {
			buf := make([]byte, length)
			if _, err := io.ReadFull(c.br, buf); err != nil {
				return nil, err
			}
			out = append(out, buf...)
		}
		if length < maxPacketLen {
			return out, nil
		}
	}
}

func (c *mysqlConn) writePacket(payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), c.seq}
	c.seq++
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

// writeResultSet 写出一个完整文本结果集（列定义 + EOF + 行 + EOF）。
func (c *mysqlConn) writeResultSet(rs mysqlResultSet) error {
	// 列数（长度编码整数）
	if err := c.writePacket(appendLenEncInt(nil, uint64(len(rs.columns)))); err != nil {
		return err
	}
	for _, col := range rs.columns {
		if err := c.writePacket(col.definition()); err != nil {
			return err
		}
	}
	if len(rs.columns) > 0 {
		if err := c.writePacket(buildEOFPacket(statusAutocommit)); err != nil {
			return err
		}
	}
	for _, row := range rs.rows {
		var p []byte
		for _, cell := range row {
			if cell == nil {
				p = append(p, 0xfb) // SQL NULL
				continue
			}
			p = appendLenEncString(p, []byte(*cell))
		}
		if err := c.writePacket(p); err != nil {
			return err
		}
	}
	// 收尾：无列时也要一个包让客户端知道没有行了
	return c.writePacket(buildEOFPacket(statusAutocommit))
}

// ---- 长度编码整数/字符串 ----

func readLenEncInt(b []byte) (val uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, 0
		}
		return uint64(b[1]) | uint64(b[2])<<8, 3
	case 0xfd:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case 0xfe:
		if len(b) < 9 {
			return 0, 0
		}
		var v uint64
		for i := 8; i >= 1; i-- {
			v = v<<8 | uint64(b[i])
		}
		return v, 9
	default:
		return uint64(b[0]), 1
	}
}

func appendLenEncInt(dst []byte, v uint64) []byte {
	switch {
	case v < 0xfb:
		return append(dst, byte(v))
	case v <= 0xffff:
		return append(dst, 0xfc, byte(v), byte(v>>8))
	case v <= 0xffffff:
		return append(dst, 0xfd, byte(v), byte(v>>8), byte(v>>16))
	default:
		return append(dst, 0xfe,
			byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
			byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
	}
}

func appendLenEncString(dst, s []byte) []byte {
	dst = appendLenEncInt(dst, uint64(len(s)))
	return append(dst, s...)
}

func appendNULString(dst []byte, s string) []byte {
	return append(append(dst, s...), 0)
}

// ---- 握手 ----

// buildGreeting 构造 Initial Handshake Packet（protocol 10）。
func buildGreeting(cfg mysqlConfig, threadID uint32, salt []byte) []byte {
	var p []byte
	p = append(p, 10) // protocol version
	p = appendNULString(p, cfg.version())
	p = append(p, byte(threadID), byte(threadID>>8), byte(threadID>>16), byte(threadID>>24))
	// auth-plugin-data-part-1：salt 前 8 字节
	p = append(p, salt[:8]...)
	p = append(p, 0x00) // filler
	p = append(p, byte(serverCapabilities), byte(serverCapabilities>>8))
	p = append(p, 0x21) // character_set = utf8_general_ci
	p = append(p, byte(statusAutocommit), 0x00)
	p = append(p, byte(serverCapabilities>>16), byte(serverCapabilities>>24))
	p = append(p, 21)                  // auth_plugin_data_len（20 字节 salt + NUL）
	p = append(p, make([]byte, 10)...) // reserved
	// auth-plugin-data-part-2：salt 后 12 字节 + NUL
	p = append(p, salt[8:20]...)
	p = append(p, 0x00)
	p = appendNULString(p, cfg.authPlugin())
	return p
}

// handshakeResponse 解析后的客户端握手响应。
type handshakeResponse struct {
	username     string
	authResponse []byte
	database     string
	authPlugin   string
	clientFlags  uint32
	maxPacket    uint32
	charset      byte
	attrs        map[string]string
}

// parseHandshakeResponse 解析 Handshake Response（protocol 41）。
func parseHandshakeResponse(b []byte) (*handshakeResponse, error) {
	r := &handshakeResponse{attrs: map[string]string{}}
	pos := 0
	need := func(n int) error {
		if pos+n > len(b) {
			return fmt.Errorf("mysql: handshake response truncated")
		}
		return nil
	}
	if err := need(4); err != nil {
		return nil, err
	}
	r.clientFlags = uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16 | uint32(b[pos+3])<<24
	pos += 4
	if err := need(4); err != nil {
		return nil, err
	}
	r.maxPacket = uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16 | uint32(b[pos+3])<<24
	pos += 4
	if err := need(1); err != nil {
		return nil, err
	}
	r.charset = b[pos]
	pos++
	pos += 23 // reserved
	if err := need(1); err != nil {
		return nil, err
	}
	// username（NUL 结尾）
	i := indexByte(b[pos:], 0)
	if i < 0 {
		return nil, fmt.Errorf("mysql: username not NUL-terminated")
	}
	r.username = string(b[pos : pos+i])
	pos += i + 1

	// auth_response：优先长度编码，其次 1 字节长度
	if r.clientFlags&capPluginAuthLenenc != 0 {
		n, adv := readLenEncInt(b[pos:])
		pos += adv
		if n > 0 {
			if err := need(int(n)); err != nil {
				return nil, err
			}
			r.authResponse = append([]byte(nil), b[pos:pos+int(n)]...)
			pos += int(n)
		}
	} else if r.clientFlags&capSecureConnection != 0 {
		if err := need(1); err != nil {
			return nil, err
		}
		n := int(b[pos])
		pos++
		if n > 0 {
			if err := need(n); err != nil {
				return nil, err
			}
			r.authResponse = append([]byte(nil), b[pos:pos+n]...)
			pos += n
		}
	} else {
		if i := indexByte(b[pos:], 0); i >= 0 {
			r.authResponse = append([]byte(nil), b[pos:pos+i]...)
			pos += i + 1
		} else {
			r.authResponse = append([]byte(nil), b[pos:]...)
			pos = len(b)
		}
	}

	if r.clientFlags&capConnectWithDB != 0 && pos < len(b) {
		if i := indexByte(b[pos:], 0); i >= 0 {
			r.database = string(b[pos : pos+i])
			pos += i + 1
		}
	}
	if r.clientFlags&capPluginAuth != 0 && pos < len(b) {
		if i := indexByte(b[pos:], 0); i >= 0 {
			r.authPlugin = string(b[pos : pos+i])
			pos += i + 1
		}
	}
	if r.clientFlags&capConnectAttrs != 0 && pos < len(b) {
		parseClientAttrs(b[pos:], r.attrs)
	}
	return r, nil
}

// parseClientAttrs 解析客户端属性块：lenenc 总长度 + 多组 (lenenc key, lenenc value)。
func parseClientAttrs(b []byte, out map[string]string) {
	total, adv := readLenEncInt(b)
	if total == 0 || adv == 0 {
		return
	}
	b = b[adv:]
	if uint64(len(b)) > total {
		b = b[:total]
	}
	pos := 0
	for pos < len(b) {
		klen, n1 := readLenEncInt(b[pos:])
		pos += n1
		if pos+int(klen) > len(b) {
			return
		}
		key := string(b[pos : pos+int(klen)])
		pos += int(klen)
		vlen, n2 := readLenEncInt(b[pos:])
		pos += n2
		if pos+int(vlen) > len(b) {
			return
		}
		out[key] = string(b[pos : pos+int(vlen)])
		pos += int(vlen)
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ---- 响应包构造 ----

func buildOKPacket(affected, lastInsertID uint64, status uint16) []byte {
	var p []byte
	p = append(p, 0x00)
	p = appendLenEncInt(p, affected)
	p = appendLenEncInt(p, lastInsertID)
	if serverCapabilities&capProtocol41 != 0 {
		p = append(p, byte(status), byte(status>>8))
		p = append(p, 0x00, 0x00) // warnings
	}
	return p
}

func buildEOFPacket(status uint16) []byte {
	var p []byte
	p = append(p, 0xfe)
	if serverCapabilities&capProtocol41 != 0 {
		p = append(p, 0x00, 0x00) // warnings
		p = append(p, byte(status), byte(status>>8))
	}
	return p
}

func buildErrPacket(code uint16, sqlState, msg string) []byte {
	var p []byte
	p = append(p, 0xff)
	p = append(p, byte(code), byte(code>>8))
	if serverCapabilities&capProtocol41 != 0 {
		p = append(p, '#')
		p = append(p, sqlState...)
	}
	return appendNULString(p, msg)
}

func buildStmtPrepareOK() []byte {
	var p []byte
	p = append(p, 0x00)       // status OK
	p = append(p, 1, 0, 0, 0) // statement id
	p = append(p, 0, 0)       // num columns
	p = append(p, 0, 0)       // num params
	p = append(p, 0)          // reserved
	p = append(p, 0x00, 0x00) // warnings
	return p
}

// ---- 结果集伪造 ----

type mysqlColumn struct {
	name    string
	colType byte
}

func (c mysqlColumn) definition() []byte {
	// 未显式指定类型时按字符串处理：colType 零值 0x00 是 MYSQL_TYPE_DECIMAL，
	// 客户端会把文本按十进制解析而崩溃（pymysql 实测踩到）。
	colType := c.colType
	if colType == 0 {
		colType = typeVarString
	}
	var p []byte
	p = appendLenEncString(p, []byte("def"))
	p = appendLenEncString(p, []byte("")) // schema
	p = appendLenEncString(p, []byte("")) // table
	p = appendLenEncString(p, []byte("")) // org_table
	p = appendLenEncString(p, []byte(c.name))
	p = appendLenEncString(p, []byte(c.name)) // org_name
	p = appendLenEncInt(p, 0x0c)              // length of fixed fields
	p = append(p, 0x21, 0x00)                 // charset utf8
	p = append(p, 0x00, 0x00, 0x00, 0x00)     // column length
	p = append(p, colType)                    // type
	p = append(p, 0x00, 0x00)                 // flags
	p = append(p, 0x00)                       // decimals
	p = append(p, 0x00, 0x00)                 // filler
	return p
}

type mysqlResultSet struct {
	columns []mysqlColumn
	rows    [][]*string
}

func strCol(name string, rows ...string) mysqlResultSet {
	cells := make([][]*string, 0, len(rows))
	for _, r := range rows {
		v := r
		cells = append(cells, []*string{&v})
	}
	return mysqlResultSet{columns: []mysqlColumn{{name: name, colType: typeVarString}}, rows: cells}
}

func varValCol(rows ...string) mysqlResultSet {
	cells := make([][]*string, 0, len(rows))
	for _, r := range rows {
		parts := strings.SplitN(r, "\t", 2)
		v := parts[1]
		cells = append(cells, []*string{&parts[0], &v})
	}
	return mysqlResultSet{
		columns: []mysqlColumn{{name: "Variable_name"}, {name: "Value"}},
		rows:    cells,
	}
}

func numCol(name string, rows ...string) mysqlResultSet {
	cells := make([][]*string, 0, len(rows))
	for _, r := range rows {
		v := r
		cells = append(cells, []*string{&v})
	}
	return mysqlResultSet{columns: []mysqlColumn{{name: name, colType: typeVarString}}, rows: cells}
}

// whitespace 归一化 SQL 用：折叠空白、去首尾分号。
var wsRe = regexp.MustCompile(`\s+`)

func normalizeSQL(sql string) string {
	s := strings.TrimSpace(sql)
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSpace(s)
	s = wsRe.ReplaceAllString(s, " ")
	return strings.ToLower(s)
}

// answer 按 SQL 语义伪造响应。返回 ok=true 表示是结果集（可能 0 行），
// ok=false 表示回 OK 包（写操作）。
func (s *mysqlSession) answer(sql string) (mysqlResultSet, bool) {
	q := normalizeSQL(sql)

	switch {
	case q == "select version()" || q == "select @@version" || q == "select version() as version":
		return strCol("VERSION()", s.cfg.version()), true
	case q == "select database()" || q == "select database" || q == "select schema()":
		if s.db == "" {
			null := (*string)(nil)
			return mysqlResultSet{
				columns: []mysqlColumn{{name: "database()", colType: typeVarString}},
				rows:    [][]*string{{null}},
			}, true
		}
		return strCol("database()", s.db), true
	case q == "select user()" || q == "select current_user()" || q == "select current_user" ||
		q == "select user" || q == "select session_user()" || q == "select system_user()":
		u := s.user
		if u == "" {
			u = "root"
		}
		return strCol("user()", u+"@localhost"), true
	case q == "select connection_id()":
		return strCol("connection_id()", "1"), true
	case q == "select now()" || q == "select current_timestamp()" || q == "select current_timestamp":
		return strCol("now()", time.Now().Format("2006-01-02 15:04:05")), true
	case q == "select unix_timestamp()" || q == "select unix_timestamp(now())":
		return strCol("unix_timestamp()", strconv.FormatInt(time.Now().Unix(), 10)), true
	case strings.HasPrefix(q, "select @@") && len(splitSelectList(strings.TrimPrefix(q, "select "))) == 1:
		return s.answerSystemVar(q), true
	case q == "show databases" || q == "show schemas":
		return strCol("Database", s.cfg.databases()...), true
	case q == "show tables" || strings.HasPrefix(q, "show tables from "):
		return strCol(fmt.Sprintf("Tables_in_%s", s.dbName()), s.cfg.tables()...), true
	case q == "show variables" || strings.HasPrefix(q, "show variables like ") ||
		strings.HasPrefix(q, "show global variables") || strings.HasPrefix(q, "show session variables"):
		rs := varValCol(
			"version\t"+s.cfg.version(),
			"version_comment\t"+s.cfg.versionComment(),
			"port\t"+strconv.FormatUint(uint64(s.port), 10),
			"datadir\t"+s.cfg.dataDir(),
			"basedir\t"+s.cfg.baseDir(),
			"socket\t"+s.cfg.socket(),
			"character_set_server\tutf8",
			"max_connections\t"+s.cfg.maxConnections(),
			"secure_file_priv\t",
			"skip_name_resolve\tOFF",
			"have_ssl\t"+s.cfg.haveSSL(),
			"sql_mode\t"+s.cfg.sqlMode(),
		)
		// SHOW VARIABLES LIKE 'x' 只回匹配行（真实 MySQL 的行为）
		if i := strings.Index(q, " like "); i >= 0 {
			rs = filterLike(rs, q[i+len(" like "):])
		}
		return rs, true
	case q == "show status" || strings.HasPrefix(q, "show global status") || strings.HasPrefix(q, "show session status"):
		return varValCol(
			"Uptime\t3600",
			"Threads_connected\t1",
			"Questions\t1",
			"Slow_queries\t0",
			"Opens\t128",
		), true
	case q == "show grants" || strings.HasPrefix(q, "show grants for "):
		u := s.user
		if u == "" {
			u = "root"
		}
		return strCol("Grants for "+u+"@localhost",
			"GRANT ALL PRIVILEGES ON *.* TO '"+u+"'@'localhost' "+s.passwordClause(u),
			"GRANT PROXY ON ''@'' TO '"+u+"'@'localhost' WITH GRANT OPTION"), true
	case q == "show engines":
		return strCol("Engine", "InnoDB", "MyISAM", "MEMORY", "CSV"), true
	case q == "show charset" || q == "show character set":
		return strCol("Charset", "utf8", "latin1", "utf8mb4"), true
	case q == "show collation":
		return strCol("Collation", "utf8_general_ci", "utf8mb4_general_ci", "latin1_swedish_ci"), true
	case q == "show processlist":
		return mysqlResultSet{
			columns: []mysqlColumn{{name: "Id"}, {name: "User"}, {name: "Host"}, {name: "db"}, {name: "Command"}, {name: "Time"}, {name: "State"}, {name: "Info"}},
			rows: [][]*string{{
				strPtr("1"), strPtr("root"), strPtr("localhost"), strPtr(s.db),
				strPtr("Query"), strPtr("0"), strPtr("executing"), strPtr(sql),
			}},
		}, true
	case q == "show warnings" || q == "show errors" || q == "show master status" || q == "show slave status" ||
		q == "show binary logs" || q == "show binlog events":
		return mysqlResultSet{columns: []mysqlColumn{{name: "Level"}}, rows: nil}, true
	case (strings.HasPrefix(q, "select") && (strings.Contains(q, "information_schema") || strings.Contains(q, "mysql.user"))):
		return projectColumns(q, s.answerInfoSchema(q)), true
	case strings.HasPrefix(q, "select") && !strings.Contains(q, " from "):
		// 无 FROM 的 SELECT：逐个解析表达式成多列单行（真实 MySQL 也是这样显示的）
		list := strings.TrimPrefix(q, "select ")
		if list == "*" {
			return mysqlResultSet{columns: []mysqlColumn{{name: ""}}, rows: nil}, true
		}
		items := splitSelectList(list)
		if len(items) == 1 {
			name, val := s.answerExpr(items[0])
			v := val
			return mysqlResultSet{
				columns: []mysqlColumn{{name: name, colType: typeVarString}},
				rows:    [][]*string{{&v}},
			}, true
		}
		cols := make([]mysqlColumn, 0, len(items))
		cells := make([]*string, 0, len(items))
		for _, it := range items {
			name, val := s.answerExpr(it)
			cols = append(cols, mysqlColumn{name: name, colType: typeVarString})
			v := val
			cells = append(cells, &v)
		}
		return mysqlResultSet{columns: cols, rows: [][]*string{cells}}, true
	case strings.HasPrefix(q, "select") || strings.HasPrefix(q, "show") ||
		strings.HasPrefix(q, "desc ") || strings.HasPrefix(q, "describe ") ||
		strings.HasPrefix(q, "explain"):
		// 未专门处理的读操作：回单列空结果集（合法，客户端显示空表）
		return mysqlResultSet{columns: []mysqlColumn{{name: ""}}, rows: nil}, true
	case strings.HasPrefix(q, "use "):
		s.db = strings.TrimSpace(strings.TrimPrefix(q, "use "))
		return mysqlResultSet{}, false
	case strings.HasPrefix(q, "set ") || strings.HasPrefix(q, "create ") ||
		strings.HasPrefix(q, "drop ") || strings.HasPrefix(q, "alter ") ||
		strings.HasPrefix(q, "insert ") || strings.HasPrefix(q, "update ") ||
		strings.HasPrefix(q, "delete ") || strings.HasPrefix(q, "truncate ") ||
		strings.HasPrefix(q, "grant ") || strings.HasPrefix(q, "revoke ") ||
		strings.HasPrefix(q, "load ") || strings.HasPrefix(q, "flush ") ||
		strings.HasPrefix(q, "begin") || strings.HasPrefix(q, "commit") ||
		strings.HasPrefix(q, "rollback") || strings.HasPrefix(q, "start"):
		// 写操作（含 INTO OUTFILE / LOAD DATA 一类外传意图）统一回 OK
		return mysqlResultSet{}, false
	default:
		return mysqlResultSet{}, false
	}
}

func (s *mysqlSession) dbName() string {
	if s.db != "" {
		return s.db
	}
	return "test"
}

func strPtr(s string) *string { return &s }

// passwordClause 生成 SHOW GRANTS 里那段认证子句（逼真的哈希，而非一眼假的
// '<secret>'）。mysql_native_password 用 *+40hex；caching_sha2_password 用
// $A$005$<salt>$<hash>，两者都按当前 auth_plugin 选择，与版本口径一致。
func (s *mysqlSession) passwordClause(u string) string {
	if s.cfg.authPlugin() == "caching_sha2_password" {
		return "IDENTIFIED WITH 'caching_sha2_password' AS " + fakeSHA2Hash()
	}
	return "IDENTIFIED BY PASSWORD " + fakeNativeHash(u)
}

// fakeNativeHash 生成 MySQL native_password 风格的 *+40 位十六进制哈希。
func fakeNativeHash(user string) string {
	sum := sha1.Sum([]byte("potagent-mysql-" + user))
	return "*" + strings.ToUpper(hex.EncodeToString(sum[:]))
}

// fakeSHA2Hash 生成 caching_sha2_password 风格的 $A$005$<salt>$<hash>。
func fakeSHA2Hash() string {
	salt := randomBytes(20)
	sum := sha256.Sum256(salt)
	return fmt.Sprintf("$A$005$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(sum[:]))
}

// projectColumns 按 SELECT 列表裁剪结果集列，让响应更接近真实 MySQL
// （客户端点名几列就回几列）。解析不出列表时原样返回。
func projectColumns(q string, rs mysqlResultSet) mysqlResultSet {
	i := strings.Index(q, "select ")
	if i < 0 {
		return rs
	}
	rest := q[i+len("select "):]
	j := strings.Index(rest, " from ")
	if j < 0 {
		return rs
	}
	list := strings.TrimSpace(rest[:j])
	if list == "" || list == "*" {
		return rs
	}
	want := make(map[string]bool)
	for _, part := range strings.Split(list, ",") {
		name := strings.TrimSpace(part)
		if k := strings.LastIndex(name, " as "); k >= 0 {
			name = strings.TrimSpace(name[:k])
		}
		if k := strings.LastIndex(name, "."); k >= 0 {
			name = name[k+1:]
		}
		name = strings.Trim(name, "`")
		if name != "" {
			want[strings.ToLower(name)] = true
		}
	}
	keep := make([]int, 0, len(rs.columns))
	for idx, c := range rs.columns {
		if want[strings.ToLower(c.name)] {
			keep = append(keep, idx)
		}
	}
	if len(keep) == 0 || len(keep) == len(rs.columns) {
		return rs
	}
	out := mysqlResultSet{columns: make([]mysqlColumn, 0, len(keep))}
	for _, idx := range keep {
		out.columns = append(out.columns, rs.columns[idx])
	}
	for _, row := range rs.rows {
		nr := make([]*string, 0, len(keep))
		for _, idx := range keep {
			if idx < len(row) {
				nr = append(nr, row[idx])
			} else {
				nr = append(nr, nil)
			}
		}
		out.rows = append(out.rows, nr)
	}
	return out
}

// filterLike 按 SHOW ... LIKE 的模式过滤行（做包含匹配，忽略引号与 %）。
func filterLike(rs mysqlResultSet, pat string) mysqlResultSet {
	pat = strings.Trim(pat, "'\"")
	pat = strings.Trim(pat, "%")
	if pat == "" {
		return rs
	}
	out := mysqlResultSet{columns: rs.columns}
	lower := strings.ToLower(pat)
	for _, row := range rs.rows {
		if len(row) > 0 && row[0] != nil && strings.Contains(strings.ToLower(*row[0]), lower) {
			out.rows = append(out.rows, row)
		}
	}
	return out
}

// splitSelectList 按顶层逗号切分 SELECT 列表（忽略括号与引号内的逗号）。
func splitSelectList(s string) []string {
	var out []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// answerExpr 解析单个 SELECT 表达式，返回（列名, 值）。未识别的表达式回空值，
// 但列名保留原样——真实 MySQL 也是这么显示的。
func (s *mysqlSession) answerExpr(expr string) (string, string) {
	e := strings.TrimSpace(expr)
	if i := strings.LastIndex(strings.ToLower(e), " as "); i >= 0 {
		e = strings.TrimSpace(e[:i])
	}
	lower := strings.ToLower(e)
	u := s.user
	if u == "" {
		u = "root"
	}
	switch {
	case lower == "version()" || lower == "@@version":
		return "VERSION()", s.cfg.version()
	case lower == "user()" || lower == "current_user()" || lower == "session_user()" ||
		lower == "system_user()" || lower == "user" || lower == "current_user":
		return "user()", u + "@localhost"
	case lower == "database()" || lower == "database" || lower == "schema()":
		return "database()", s.db
	case lower == "connection_id()":
		return "connection_id()", "1"
	case lower == "now()" || lower == "current_timestamp()" || lower == "current_timestamp" ||
		lower == "sysdate()" || lower == "localtime()":
		return "now()", time.Now().Format("2006-01-02 15:04:05")
	case lower == "unix_timestamp()" || lower == "unix_timestamp(now())":
		return "unix_timestamp()", strconv.FormatInt(time.Now().Unix(), 10)
	case lower == "last_insert_id()" || lower == "row_count()" || lower == "found_rows()":
		return lower, "0"
	case strings.HasPrefix(lower, "@@"):
		name := lower
		if i := strings.IndexAny(name, " ,"); i >= 0 {
			name = name[:i]
		}
		name = strings.Trim(name, "`")
		rs := s.answerSystemVar(name)
		if len(rs.rows) > 0 && rs.rows[0][0] != nil {
			return name, *rs.rows[0][0]
		}
		return name, ""
	default:
		return e, ""
	}
}

// answerSystemVar 伪造 @@xxx 系统变量查询。
func (s *mysqlSession) answerSystemVar(q string) mysqlResultSet {
	// 取出变量名（去掉 select / 后面的括号与别名）
	name := strings.TrimPrefix(q, "select ")
	if i := strings.IndexAny(name, " ,"); i >= 0 {
		name = name[:i]
	}
	name = strings.Trim(name, "`")
	vars := map[string]string{
		"@@version":                       s.cfg.version(),
		"@@version_comment":               s.cfg.versionComment(),
		"@@datadir":                       s.cfg.dataDir(),
		"@@basedir":                       s.cfg.baseDir(),
		"@@socket":                        s.cfg.socket(),
		"@@port":                          strconv.FormatUint(uint64(s.port), 10),
		"@@hostname":                      s.cfg.hostname(),
		"@@character_set_server":          "utf8",
		"@@max_connections":               s.cfg.maxConnections(),
		"@@secure_file_priv":              "",
		"@@have_ssl":                      s.cfg.haveSSL(),
		"@@skip_name_resolve":             "OFF",
		"@@sql_mode":                      s.cfg.sqlMode(),
		"@@time_zone":                     "SYSTEM",
		"@@system_time_zone":              "UTC",
		"@@max_allowed_packet":            "4194304",
		"@@wait_timeout":                  "28800",
		"@@default_authentication_plugin": s.cfg.authPlugin(),
	}
	col := name
	if v, ok := vars[name]; ok {
		return strCol(col, v)
	}
	return strCol(col, "")
}

// answerInfoSchema 伪造 information_schema 相关查询。
func (s *mysqlSession) answerInfoSchema(q string) mysqlResultSet {
	switch {
	case strings.Contains(q, "information_schema.schemata"):
		rows := make([][]*string, 0)
		for _, d := range s.cfg.databases() {
			rows = append(rows, []*string{strPtr(d), strPtr("utf8"), strPtr("utf8_general_ci"), strPtr("NULL")})
		}
		return mysqlResultSet{
			columns: []mysqlColumn{{name: "CATALOG_NAME"}, {name: "SCHEMA_NAME"}, {name: "DEFAULT_CHARACTER_SET_NAME"}, {name: "DEFAULT_COLLATION_NAME"}, {name: "SQL_PATH"}},
			rows:    rows,
		}
	case strings.Contains(q, "information_schema.tables"):
		rows := make([][]*string, 0)
		for _, d := range s.cfg.databases() {
			for _, t := range s.cfg.tables() {
				rows = append(rows, []*string{strPtr(d), strPtr(t), strPtr("BASE TABLE"), strPtr("InnoDB")})
			}
		}
		return mysqlResultSet{
			columns: []mysqlColumn{{name: "TABLE_SCHEMA"}, {name: "TABLE_NAME"}, {name: "TABLE_TYPE"}, {name: "ENGINE"}},
			rows:    rows,
		}
	case strings.Contains(q, "information_schema.columns"):
		rows := make([][]*string, 0)
		for _, t := range s.cfg.tables() {
			rows = append(rows, []*string{strPtr(s.dbName()), strPtr(t), strPtr("id"), strPtr("1"), strPtr("int"), strPtr("NO"), strPtr("PRI")})
			rows = append(rows, []*string{strPtr(s.dbName()), strPtr(t), strPtr("name"), strPtr("2"), strPtr("varchar(64)"), strPtr("YES"), strPtr("")})
			rows = append(rows, []*string{strPtr(s.dbName()), strPtr(t), strPtr("password"), strPtr("3"), strPtr("varchar(255)"), strPtr("YES"), strPtr("")})
		}
		return mysqlResultSet{
			columns: []mysqlColumn{{name: "TABLE_SCHEMA"}, {name: "TABLE_NAME"}, {name: "COLUMN_NAME"}, {name: "ORDINAL_POSITION"}, {name: "COLUMN_TYPE"}, {name: "IS_NULLABLE"}, {name: "COLUMN_KEY"}},
			rows:    rows,
		}
	case strings.Contains(q, "information_schema.user_privileges") || strings.Contains(q, "mysql.user"):
		rows := make([][]*string, 0)
		for _, d := range s.cfg.databases() {
			rows = append(rows, []*string{strPtr("'root'@'localhost'"), strPtr(d), strPtr("ALL PRIVILEGES")})
		}
		return mysqlResultSet{
			columns: []mysqlColumn{{name: "GRANTEE"}, {name: "TABLE_SCHEMA"}, {name: "PRIVILEGE_TYPE"}},
			rows:    rows,
		}
	default:
		return mysqlResultSet{columns: []mysqlColumn{{name: ""}}, rows: nil}
	}
}

// randomBytes 返回 n 字节加密随机数。
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i)
		}
	}
	return b
}
