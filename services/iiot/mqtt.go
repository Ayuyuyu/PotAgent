package iiot

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

// MQTT 控制报文类型（固定报头高 4 位）
const (
	mqttPacketConnect     = 0x1
	mqttPacketConnack     = 0x2
	mqttPacketPublish     = 0x3
	mqttPacketPuback      = 0x4
	mqttPacketPubrec      = 0x5
	mqttPacketPubrel      = 0x6
	mqttPacketPubcomp     = 0x7
	mqttPacketSubscribe   = 0x8
	mqttPacketSuback      = 0x9
	mqttPacketUnsubscribe = 0xA
	mqttPacketUnsuback    = 0xB
	mqttPacketPingreq     = 0xC
	mqttPacketPingresp    = 0xD
	mqttPacketDisconnect  = 0xE
)

const (
	// mqttMaxRemainingLength 是剩余长度字段的防呆上限（4MB）。
	mqttMaxRemainingLength = 4 << 20
	// mqttAreaPrefix 是 dataStore 里“保留消息”的区名前缀（retained message，重启后仍在）。
	mqttAreaPrefix = "mqtt-topic-"
	// mqttMaxLoggedPayload 是事件里记录的 payload 上限，避免超大报文撑爆日志。
	mqttMaxLoggedPayload = 512
)

// mqttPacketNames 让事件里的报文类型可读。
var mqttPacketNames = map[byte]string{
	mqttPacketConnect:     "connect",
	mqttPacketConnack:     "connack",
	mqttPacketPublish:     "publish",
	mqttPacketPuback:      "puback",
	mqttPacketPubrec:      "pubrec",
	mqttPacketPubrel:      "pubrel",
	mqttPacketPubcomp:     "pubcomp",
	mqttPacketSubscribe:   "subscribe",
	mqttPacketSuback:      "suback",
	mqttPacketUnsubscribe: "unsubscribe",
	mqttPacketUnsuback:    "unsuback",
	mqttPacketPingreq:     "pingreq",
	mqttPacketPingresp:    "pingresp",
	mqttPacketDisconnect:  "disconnect",
}

func mqttPacketName(packetType byte) string {
	if name, ok := mqttPacketNames[packetType]; ok {
		return name
	}
	return fmt.Sprintf("type-%#x", packetType)
}

// mqttMessage 是一条要发给订阅者的消息。
type mqttMessage struct {
	topic   string
	payload []byte
	qos     byte
	retain  bool
}

// mqttBroker 是同一个服务实例上的“在线会话表”（每个 yaml 配置一份）。
// 用途：PUBLISH 实时转发给当前已订阅的客户端——这样 retain=0 的报文也能被在线订阅者读到；
// 保留消息（retain=1）另外落在 dataStore 里，供以后任何订阅者回放。
type mqttBroker struct {
	mu       sync.Mutex
	sessions map[*mqttSession]struct{}
	nextID   uint16
}

func newMQTTBroker() *mqttBroker {
	return &mqttBroker{sessions: make(map[*mqttSession]struct{}), nextID: 1}
}

func (b *mqttBroker) add(session *mqttSession) {
	if b == nil || session == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions[session] = struct{}{}
}

func (b *mqttBroker) remove(session *mqttSession) {
	if b == nil || session == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, session)
}

// nextPacketID 给出站 QoS>0 报文分配报文标识符。
func (b *mqttBroker) nextPacketID() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	if b.nextID == 0 {
		b.nextID = 1
	}
	return id
}

// forward 把一条发布实时转发给所有匹配的在线订阅者，返回成功写出的连接数。
// 出站一律按订阅时授予的 QoS 降级（min(发布 QoS, 订阅 QoS)），避免半成品的 QoS 状态机。
func (b *mqttBroker) forward(topic string, payload []byte, qos byte) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	sessions := make([]*mqttSession, 0, len(b.sessions))
	for session := range b.sessions {
		sessions = append(sessions, session)
	}
	b.mu.Unlock()

	delivered := 0
	for _, session := range sessions {
		granted, ok := session.match(topic)
		if !ok {
			continue
		}
		deliverQoS := minByte(qos, granted)
		if err := session.write(mqttPublishPacket(topic, payload, deliverQoS, false, b.nextPacketID())); err == nil {
			delivered++
		}
	}
	return delivered
}

// mqttSession 是一条 MQTT 连接上的会话状态：订阅关系 + 串行化的写。
type mqttSession struct {
	conn net.Conn
	mu   sync.Mutex
	subs map[string]byte // 订阅过滤器 -> 授予的 QoS
}

func newMQTTSession(conn net.Conn) *mqttSession {
	return &mqttSession{conn: conn, subs: make(map[string]byte)}
}

func (s *mqttSession) write(packet []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write(packet)
	return err
}

func (s *mqttSession) subscribe(filter string, qos byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[filter] = qos
}

func (s *mqttSession) unsubscribe(filter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, filter)
}

// match 返回命中的订阅里最高的授予 QoS。
func (s *mqttSession) match(topic string) (byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	granted, ok := byte(0), false
	for filter, qos := range s.subs {
		if mqttTopicMatch(filter, topic) && (!ok || qos > granted) {
			granted, ok = qos, true
		}
	}
	return granted, ok
}

// handleMQTT 处理 MQTT 3.1 / 3.1.1 / 5 的客户端报文：
// CONNECT→CONNACK（用户名/密码/遗嘱/CleanSession 都记事件）、SUBSCRIBE→SUBACK（随后回放保留消息）、
// PUBLISH（QoS1/2 回 PUBACK/PUBREC；retain=1 落 dataStore 供后续订阅者读取，
// 同时实时转发给在线订阅者）、PINGREQ→PINGRESP 等。
func handleMQTT(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore,
	broker *mqttBroker, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	session := newMQTTSession(conn)
	defer broker.remove(session)

	level := byte(4) // 协商出的协议级别（3=3.1，4=3.1.1，5=MQTT5）
	connected := false

	for {
		head, err := readFull(conn, 1)
		if err != nil {
			return
		}
		remaining, err := readMQTTRemainingLength(conn)
		if err != nil {
			return
		}
		body, err := readFull(conn, remaining)
		if err != nil {
			return
		}
		packetType := head[0] >> 4
		flags := head[0] & 0x0F

		raw := append([]byte{}, head...)
		raw = append(raw, mqttEncodeRemainingLength(remaining)...)
		raw = append(raw, body...)

		details := map[string]interface{}{
			"ics.raw":          rawHex(raw),
			"mqtt.packet":      mqttPacketName(packetType),
			"mqtt.packet-type": packetType,
		}

		// CONNECT 必须是第一个报文，否则像真实 broker 一样断开
		if !connected && packetType != mqttPacketConnect {
			details["ics.operation"] = "not-connected"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			return
		}

		var responses [][]byte
		switch packetType {
		case mqttPacketConnect:
			ack, negotiated, keepGoing := mqttHandleConnect(body, details)
			if ack != nil {
				responses = append(responses, ack)
			}
			level = negotiated
			connected = keepGoing
			if keepGoing {
				broker.add(session)
			} else {
				pushICS(protocol+"-request", src, dst, service, cfg, details)
				return
			}
		case mqttPacketPublish:
			details["mqtt.flags"] = flags
			responses = mqttHandlePublish(body, level, flags, cfg, store, broker, details)
		case mqttPacketSubscribe:
			responses = mqttHandleSubscribe(body, level, cfg, store, broker, session, details)
		case mqttPacketUnsubscribe:
			responses = mqttHandleUnsubscribe(body, level, session, details)
		case mqttPacketPingreq:
			details["ics.operation"] = "pingreq"
			responses = [][]byte{{mqttPacketPingresp << 4, 0x00}}
		case mqttPacketDisconnect:
			details["ics.operation"] = "disconnect"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			return
		case mqttPacketPubrec:
			// 我们发出去的 QoS2 消息，对端回 PUBREC → 回 PUBREL 完成握手
			details["ics.operation"] = "pubrec"
			if packetID, ok := mqttPacketID(body); ok {
				details["mqtt.packet-id"] = packetID
				responses = [][]byte{mqttPacketIDOnly(mqttPacketPubrel, packetID)}
			}
		case mqttPacketPubrel:
			// 客户端发来的 QoS2 消息，回 PUBCOMP
			details["ics.operation"] = "pubrel"
			if packetID, ok := mqttPacketID(body); ok {
				details["mqtt.packet-id"] = packetID
				responses = [][]byte{mqttPacketIDOnly(mqttPacketPubcomp, packetID)}
			}
		default:
			// PUBACK/PUBCOMP/CONNACK 等由客户端发来的报文只记事件
			details["ics.operation"] = mqttPacketName(packetType)
			if packetID, ok := mqttPacketID(body); ok {
				details["mqtt.packet-id"] = packetID
			}
		}

		pushICS(protocol+"-request", src, dst, service, cfg, details)
		for _, packet := range responses {
			if err := session.write(packet); err != nil {
				logger.Log.Debug("iiot: mqtt write response failed: ", err)
				return
			}
		}
	}
}

// mqttHandleConnect 解析 CONNECT 并回 CONNACK；返回 (CONNACK, 协议级别, 是否继续会话)。
func mqttHandleConnect(body []byte, details map[string]interface{}) ([]byte, byte, bool) {
	r := mqttReader{data: body}
	protocolName, ok := r.binary()
	if !ok {
		details["ics.operation"] = "connect-malformed"
		return nil, 4, false
	}
	level, ok := r.uint8()
	if !ok {
		details["ics.operation"] = "connect-malformed"
		return nil, 4, false
	}
	flags, ok := r.uint8()
	if !ok {
		details["ics.operation"] = "connect-malformed"
		return nil, level, false
	}
	keepalive, ok := r.uint16()
	if !ok {
		details["ics.operation"] = "connect-malformed"
		return nil, level, false
	}

	details["ics.operation"] = "connect"
	details["mqtt.protocol-name"] = string(protocolName)
	details["mqtt.version"] = level
	details["mqtt.keepalive"] = keepalive
	details["mqtt.clean-session"] = flags&0x02 != 0
	details["mqtt.username-flag"] = flags&0x80 != 0
	details["mqtt.password-flag"] = flags&0x40 != 0

	// MQTT 5 的变量头后面还有属性块
	if level == 5 && !r.skipProperties() {
		details["ics.operation"] = "connect-malformed"
		return nil, level, false
	}

	clientID, _ := r.binary()
	details["mqtt.client-id"] = string(clientID)

	if flags&0x04 != 0 { // 遗嘱消息
		if topic, ok := r.binary(); ok {
			details["mqtt.will-topic"] = string(topic)
			details["mqtt.will-qos"] = (flags >> 3) & 0x03
			details["mqtt.will-retain"] = flags&0x20 != 0
			if payload, ok := r.binary(); ok {
				details["mqtt.will-payload"] = mqttPayloadString(payload)
			}
		}
	}
	if flags&0x80 != 0 { // 用户名
		if username, ok := r.binary(); ok {
			details["mqtt.username"] = string(username)
		}
	}
	if flags&0x40 != 0 { // 密码
		if password, ok := r.binary(); ok {
			details["mqtt.password"] = string(password)
		}
	}

	// 只接受 3.1(3) / 3.1.1(4) / MQTT5，其余按规范回“不可接受的协议版本”
	if level != 3 && level != 4 && level != 5 {
		details["mqtt.return-code"] = 1
		return mqttConnack(4, 1), level, false
	}
	details["mqtt.return-code"] = 0
	return mqttConnack(level, 0), level, true
}

// mqttConnack 构造 CONNACK（v5 比 v3/v4 多 1 字节属性长度）。
func mqttConnack(level, returnCode byte) []byte {
	if level == 5 {
		return []byte{mqttPacketConnack << 4, 0x03, 0x00, returnCode, 0x00}
	}
	return []byte{mqttPacketConnack << 4, 0x02, 0x00, returnCode}
}

// mqttHandlePublish 解析 PUBLISH：
//   - retain=1：作为保留消息存入 dataStore（重启后仍可被订阅者读到；空 payload 表示清除该主题）；
//   - retain=0：不落存储，但会实时转发给当前在线的订阅者；
//   - QoS1/2：分别回 PUBACK / PUBREC（后续 PUBREL→PUBCOMP）。
func mqttHandlePublish(body []byte, level, flags byte, cfg *iiotConfig, store *dataStore,
	broker *mqttBroker, details map[string]interface{}) [][]byte {
	r := mqttReader{data: body}
	topic, ok := r.binary()
	if !ok {
		details["ics.operation"] = "publish-malformed"
		return nil
	}
	qos := (flags >> 1) & 0x03
	retain := flags&0x01 != 0
	details["ics.operation"] = "publish"
	details["mqtt.topic"] = string(topic)
	details["mqtt.qos"] = qos
	details["mqtt.retain"] = retain
	details["mqtt.dup"] = flags&0x08 != 0

	var packetID uint16
	if qos > 0 {
		packetID, ok = r.uint16()
		if !ok {
			details["ics.operation"] = "publish-malformed"
			return nil
		}
		details["mqtt.packet-id"] = packetID
	}
	if level == 5 && !r.skipProperties() {
		details["ics.operation"] = "publish-malformed"
		return nil
	}

	payload := r.rest()
	details["mqtt.payload"] = mqttPayloadString(payload)

	// 保留消息：存起来供以后订阅的客户端读取（retain_all 打开时所有发布都算）
	if retain || cfg != nil && cfg.RetainAll {
		if len(payload) == 0 {
			store.del(mqttAreaPrefix + string(topic))
			details["mqtt.retained"] = "cleared"
		} else if store.set(mqttAreaPrefix+string(topic), payload) {
			details["mqtt.retained"] = "stored"
		}
	}

	// 实时转发给当前已订阅的客户端
	if delivered := broker.forward(string(topic), payload, qos); delivered > 0 {
		details["mqtt.forwarded"] = delivered
	}

	switch qos {
	case 1:
		return [][]byte{mqttPacketIDOnly(mqttPacketPuback, packetID)}
	case 2:
		return [][]byte{mqttPacketIDOnly(mqttPacketPubrec, packetID)}
	}
	return nil
}

// mqttHandleSubscribe 解析 SUBSCRIBE，回 SUBACK，记录订阅关系，
// 并把保留消息（之前 retain=1 的发布 + 配置里的预置初值）回放给这个客户端。
func mqttHandleSubscribe(body []byte, level byte, cfg *iiotConfig, store *dataStore,
	broker *mqttBroker, session *mqttSession, details map[string]interface{}) [][]byte {
	r := mqttReader{data: body}
	packetID, ok := r.uint16()
	if !ok {
		details["ics.operation"] = "subscribe-malformed"
		return nil
	}
	if level == 5 && !r.skipProperties() {
		details["ics.operation"] = "subscribe-malformed"
		return nil
	}

	type subscription struct {
		filter string
		qos    byte
	}
	var subs []subscription
	for {
		filter, ok := r.binary()
		if !ok {
			break
		}
		qos, ok := r.uint8()
		if !ok {
			break
		}
		if qos > 2 {
			qos = 2
		}
		subs = append(subs, subscription{filter: string(filter), qos: qos})
	}
	if len(subs) == 0 {
		details["ics.operation"] = "subscribe-empty"
		return nil
	}

	filters := make([]string, 0, len(subs))
	granted := make([]byte, 0, len(subs))
	for _, sub := range subs {
		filters = append(filters, sub.filter)
		granted = append(granted, sub.qos)
		session.subscribe(sub.filter, sub.qos)
	}
	details["ics.operation"] = "subscribe"
	details["mqtt.packet-id"] = packetID
	details["mqtt.topics"] = strings.Join(filters, ",")

	// SUBACK：剩余长度 = 报文标识符(2) + [v5 属性长度(1)] + 每个订阅的结果(1)
	suback := []byte{mqttPacketSuback << 4}
	if level == 5 {
		suback = append(suback, byte(3+len(granted)), byte(packetID>>8), byte(packetID), 0x00)
	} else {
		suback = append(suback, byte(2+len(granted)), byte(packetID>>8), byte(packetID))
	}
	suback = append(suback, granted...)
	responses := [][]byte{suback}

	// 回放保留消息：RETAIN 标志置 1，QoS 取 min(保留消息 QoS, 订阅授予 QoS)
	delivered := 0
	for _, sub := range subs {
		for _, message := range mqttSubscribedMessages(cfg, store, sub.filter) {
			deliverQoS := minByte(message.qos, sub.qos)
			responses = append(responses,
				mqttPublishPacket(message.topic, message.payload, deliverQoS, true, broker.nextPacketID()))
			delivered++
		}
	}
	if delivered > 0 {
		details["mqtt.retained-delivered"] = delivered
	}
	return responses
}

// mqttHandleUnsubscribe 解析 UNSUBSCRIBE，回 UNSUBACK 并删除订阅关系。
func mqttHandleUnsubscribe(body []byte, level byte, session *mqttSession, details map[string]interface{}) [][]byte {
	r := mqttReader{data: body}
	packetID, ok := r.uint16()
	if !ok {
		details["ics.operation"] = "unsubscribe-malformed"
		return nil
	}
	if level == 5 && !r.skipProperties() {
		details["ics.operation"] = "unsubscribe-malformed"
		return nil
	}
	var filters []string
	for {
		filter, ok := r.binary()
		if !ok {
			break
		}
		filters = append(filters, string(filter))
		session.unsubscribe(string(filter))
	}
	details["ics.operation"] = "unsubscribe"
	details["mqtt.packet-id"] = packetID
	details["mqtt.topics"] = strings.Join(filters, ",")
	return [][]byte{mqttPacketIDOnly(mqttPacketUnsuback, packetID)}
}

// mqttSubscribedMessages 取某个订阅过滤器命中的保留消息：
// 配置里的预置主题（若该主题被 retain 发布过则用最新 payload）+ dataStore 里的保留消息。
func mqttSubscribedMessages(cfg *iiotConfig, store *dataStore, filter string) []mqttMessage {
	var out []mqttMessage
	seen := make(map[string]bool)
	if cfg != nil {
		for _, topic := range cfg.Topics {
			if !mqttTopicMatch(filter, topic.Topic) {
				continue
			}
			payload := []byte(topic.Payload)
			if stored := store.get(mqttAreaPrefix + topic.Topic); len(stored) > 0 {
				payload = stored
			}
			out = append(out, mqttMessage{topic: topic.Topic, payload: payload, qos: topic.QoS, retain: true})
			seen[topic.Topic] = true
		}
	}
	for topic, payload := range store.snapshot(mqttAreaPrefix) {
		if seen[topic] || !mqttTopicMatch(filter, topic) {
			continue
		}
		out = append(out, mqttMessage{topic: topic, payload: payload, qos: 0, retain: true})
	}
	return out
}

// mqttTopicMatch 判断主题是否匹配订阅过滤器（支持 + 单层、# 多层通配）。
func mqttTopicMatch(filter, topic string) bool {
	if filter == topic {
		return true
	}
	filterLevels := strings.Split(filter, "/")
	topicLevels := strings.Split(topic, "/")
	for i, level := range filterLevels {
		if level == "#" {
			return true
		}
		if i >= len(topicLevels) {
			return false
		}
		if level == "+" {
			continue
		}
		if level != topicLevels[i] {
			return false
		}
	}
	return len(filterLevels) == len(topicLevels)
}

// mqttPublishPacket 构造一条 PUBLISH：QoS>0 时必须带报文标识符。
func mqttPublishPacket(topic string, payload []byte, qos byte, retain bool, packetID uint16) []byte {
	header := byte(mqttPacketPublish<<4) | (qos&0x03)<<1
	if retain {
		header |= 0x01
	}
	body := make([]byte, 0, 4+len(topic)+len(payload))
	body = append(body, byte(len(topic)>>8), byte(len(topic)))
	body = append(body, topic...)
	if qos > 0 {
		body = append(body, byte(packetID>>8), byte(packetID))
	}
	body = append(body, payload...)

	packet := []byte{header}
	packet = append(packet, mqttEncodeRemainingLength(len(body))...)
	return append(packet, body...)
}

// mqttPacketIDOnly 构造只带报文标识符的确认报文（PUBACK/PUBREC/PUBREL/PUBCOMP/UNSUBACK 通用）。
func mqttPacketIDOnly(packetType byte, packetID uint16) []byte {
	return []byte{packetType << 4, 0x02, byte(packetID >> 8), byte(packetID)}
}

// mqttPacketID 从报文体里取报文标识符（前 2 字节）。
func mqttPacketID(body []byte) (uint16, bool) {
	if len(body) < 2 {
		return 0, false
	}
	return uint16(body[0])<<8 | uint16(body[1]), true
}

// mqttPayloadString 让事件里的 payload 尽量可读：可打印用原文，否则用 hex；超长截断。
func mqttPayloadString(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	truncated := false
	if len(payload) > mqttMaxLoggedPayload {
		payload = payload[:mqttMaxLoggedPayload]
		truncated = true
	}
	printable := true
	for _, b := range payload {
		if b < 0x20 || b > 0x7E {
			printable = false
			break
		}
	}
	out := rawHex(payload)
	if printable {
		out = string(payload)
	}
	if truncated {
		out += "...(truncated)"
	}
	return out
}

// readMQTTRemainingLength 读取“剩余长度”变长字段（7 位一组，最多 4 字节）。
func readMQTTRemainingLength(conn net.Conn) (int, error) {
	value, multiplier := 0, 1
	for i := 0; i < 4; i++ {
		b, err := readFull(conn, 1)
		if err != nil {
			return 0, err
		}
		value += int(b[0]&0x7F) * multiplier
		if b[0]&0x80 == 0 {
			if value > mqttMaxRemainingLength {
				return 0, fmt.Errorf("iiot: mqtt remaining length too large: %d", value)
			}
			return value, nil
		}
		multiplier *= 128
	}
	return 0, fmt.Errorf("iiot: mqtt remaining length malformed")
}

func mqttEncodeRemainingLength(n int) []byte {
	out := make([]byte, 0, 4)
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		out = append(out, digit)
		if n == 0 {
			return out
		}
	}
}

// mqttReader 顺序读取 MQTT 报文里的字段（大端长度前缀、VLI 等）。
type mqttReader struct {
	data []byte
	pos  int
}

func (r *mqttReader) uint8() (byte, bool) {
	if r.pos >= len(r.data) {
		return 0, false
	}
	v := r.data[r.pos]
	r.pos++
	return v, true
}

func (r *mqttReader) uint16() (uint16, bool) {
	if r.pos+2 > len(r.data) {
		return 0, false
	}
	v := uint16(r.data[r.pos])<<8 | uint16(r.data[r.pos+1])
	r.pos += 2
	return v, true
}

// binary 读 2 字节长度前缀的字段。
func (r *mqttReader) binary() ([]byte, bool) {
	n, ok := r.uint16()
	if !ok || r.pos+int(n) > len(r.data) {
		return nil, false
	}
	v := r.data[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return v, true
}

func (r *mqttReader) rest() []byte {
	v := r.data[r.pos:]
	r.pos = len(r.data)
	return v
}

// varint 读变长整数（MQTT 5 属性长度）。
func (r *mqttReader) varint() (int, bool) {
	value, multiplier := 0, 1
	for i := 0; i < 4; i++ {
		b, ok := r.uint8()
		if !ok {
			return 0, false
		}
		value += int(b&0x7F) * multiplier
		if b&0x80 == 0 {
			return value, true
		}
		multiplier *= 128
	}
	return 0, false
}

// skipProperties 跳过 MQTT 5 的属性块。
func (r *mqttReader) skipProperties() bool {
	n, ok := r.varint()
	if !ok || r.pos+n > len(r.data) {
		return false
	}
	r.pos += n
	return true
}

// minByte 取两个 byte 的较小值（QoS 降级用）。
func minByte(a, b byte) byte {
	if a < b {
		return a
	}
	return b
}
