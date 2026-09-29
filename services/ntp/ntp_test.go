package ntp

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"potAgent/global"
	"potAgent/logger"
)

func TestNTPStamp(t *testing.T) {
	// 1970-01-01 00:00:00 UTC 的 NTP 秒应为纪元偏移量，纳秒为 0
	base := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	sec, frac := ntpStamp(base)
	if sec != ntpEpochOffset {
		t.Fatalf("ntpStamp 秒期望 %d, 实际 %d", ntpEpochOffset, sec)
	}
	if frac != 0 {
		t.Fatalf("ntpStamp 分数期望 0, 实际 %d", frac)
	}
}

func TestBuildNTPResponse(t *testing.T) {
	// 构造一个 48 字节请求：VN=4、Mode=3(client)，Transmit Timestamp=0x11223344.55667788
	req := make([]byte, ntpSize)
	req[0] = (4 << 3) | 0x3
	binary.BigEndian.PutUint64(req[40:48], 0x1122334455667788)

	resp := buildNTPResponse(req, &ntpConfig{Stratum: 2}, refID4("LOCL"), 4)

	if len(resp) != ntpSize {
		t.Fatalf("响应长度期望 %d, 实际 %d", ntpSize, len(resp))
	}
	// 首字节：LI=0, VN=4, Mode=4 => 0x24
	if resp[0] != 0x24 {
		t.Fatalf("首字节期望 0x24, 实际 0x%02x", resp[0])
	}
	if resp[1] != 2 {
		t.Fatalf("stratum 期望 2, 实际 %d", resp[1])
	}
	if resp[2] != 10 {
		t.Fatalf("poll 期望 10, 实际 %d", resp[2])
	}
	if resp[3] != 0xEC {
		t.Fatalf("precision 期望 0xEC, 实际 0x%02x", resp[3])
	}
	// reference id = "LOCL"
	if string(resp[12:16]) != "LOCL" {
		t.Fatalf("reference id 期望 LOCL, 实际 %q", resp[12:16])
	}
	// originate timestamp 应回显客户端 transmit ts
	if got := binary.BigEndian.Uint64(resp[24:32]); got != 0x1122334455667788 {
		t.Fatalf("originate ts 期望 0x1122334455667788, 实际 0x%016x", got)
	}
	// receive/transmit timestamp 应为合理（> 纪元偏移）
	nowSec := uint32(time.Now().Unix() + ntpEpochOffset)
	if got := binary.BigEndian.Uint64(resp[32:40]) >> 32; got < uint64(nowSec)-2 || got > uint64(nowSec)+2 {
		t.Fatalf("receive ts 秒超出预期范围: %d (期望约 %d)", got, nowSec)
	}
}

// TestNTPServiceRoundTrip：真实起 UDP 监听，发请求收响应，校验能解析出合理时间。
func TestNTPServiceRoundTrip(t *testing.T) {
	logger.InitLog("info")
	port := freeUDPPort(t)

	svc := NTPServiceInit()
	svc.BaseOptions = global.ServiceBaseConfig{
		Protocol:    "ntp",
		Application: "ntp",
		Host:        "127.0.0.1",
		Port:        uint16(port),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ntpHandle(ctx, &svc)

	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req := make([]byte, ntpSize)
	req[0] = (4 << 3) | 0x3
	var resp []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client.SetDeadline(deadline)
		if _, err := client.Write(req); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		n, err := client.Read(buf)
		if err == nil && n >= ntpSize {
			resp = buf[:n]
			break
		}
	}
	if resp == nil {
		t.Fatal("未收到 NTP 响应")
	}
	if resp[0]&0x07 != 0x4 {
		t.Fatalf("响应 Mode 期望 4(server), 实际 %d", resp[0]&0x07)
	}
	sec := binary.BigEndian.Uint64(resp[40:48]) >> 32
	// 响应时间应接近当前 NTP 秒（容差 5s）
	want := uint32(time.Now().Unix() + ntpEpochOffset)
	if sec < uint64(want)-5 || sec > uint64(want)+5 {
		t.Fatalf("响应时间异常: %d (期望约 %d)", sec, want)
	}
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
